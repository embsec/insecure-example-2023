// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h"  // Peripheral Bit Masks and Registers
#include "inc/hw_types.h"  // Boolean type
#include "inc/hw_ints.h"   // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/sysctl.h"    // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API

// Library Imports
#include <string.h>
#include <beaverssl.h> // Crypto library

// Application Imports
#include "uart.h"
#include "../keys.h" // Key/AAD stored here

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char *, unsigned int);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define END ((unsigned char)0x02)
#define TYPE ((unsigned char)0x04)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Firmware v2 is embedded in bootloader
// Read up on these symbols in the objcopy man page (if you want)!
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
uint16_t *fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t *fw_release_message_address;
void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len);

// Firmware Buffer
unsigned char complete_data[1024];

/* ****************************************************************
 *
 * Intilializes UARTS.
 * 
 * At start-up, allows user to choose whether to update, or boot
 * firmware
 * 
 * ****************************************************************
*/
int main(void){

    // A 'reset' on UART0 will re-start this code at the top of main, won't clear flash, but will clean ram.

    // Initialize UART channels
    // 0: Reset
    // 1: Host Connection
    // 2: Debug
    uart_init(UART0);
    uart_init(UART1);
    uart_init(UART2);

    // Enable UART0 interrupt
    IntEnable(INT_UART0);
    IntMasterEnable();

    load_initial_firmware(); // note the short-circuit behavior in this function, it doesn't finish running on reset!

    uart_write_str(UART2, "\nWelcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
    uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

    // Boots or downloads new firmware based on user response
    int resp;
    while (1){
        uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
        if (instruction == UPDATE){
            uart_write_str(UART1, "U");
            load_firmware();
            uart_write_str(UART2, "Loaded new firmware.\n");
            nl(UART2);
        }else if (instruction == BOOT){
            uart_write_str(UART1, "B");
            boot_firmware();
        }
    }
}

/* ****************************************************************
 *
 * Loads the initial firmware into flash V2 if there has been no
 * reset
 * 
 * ****************************************************************
 */
void load_initial_firmware(void){

    if (*((uint32_t *)(METADATA_BASE)) != 0xFFFFFFFF){
        /*
         * Default Flash startup state is all FF since. Only load initial
         * firmware when metadata page is all FF. Thus, exit if there has
         * been a reset!
         */
        return;
    }

    // Create buffers for saving the release message
    uint8_t temp_buf[FLASH_PAGESIZE];
    char initial_msg[] = "This is the initial release message.";
    uint16_t msg_len = strlen(initial_msg) + 1;
    uint16_t rem_msg_bytes;

    // Get included initial firmware
    int size = (int)&_binary_firmware_bin_size;
    uint8_t *initial_data = (uint8_t *)&_binary_firmware_bin_start;

    // Set version 2 and install
    uint16_t version = 2;
    uint32_t metadata = (((uint16_t)size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    int i;

    for (i = 0; i < size / FLASH_PAGESIZE; i++){
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), initial_data + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
    }

    /* At end of firmware. Since the last page may be incomplete, we copy the initial
     * release message into the unused space in the last page. If the firmware fully
     * uses the last page, the release message simply is written to a new page.
     */

    uint16_t rem_fw_bytes = size % FLASH_PAGESIZE;
    if (rem_fw_bytes == 0){
        // No firmware left. Just write the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)initial_msg, msg_len);
    }else{
        // Some firmware left. Determine how many bytes of release message can fit
        if (msg_len > (FLASH_PAGESIZE - rem_fw_bytes)){
            rem_msg_bytes = msg_len - (FLASH_PAGESIZE - rem_fw_bytes);
        }else{
            rem_msg_bytes = 0;
        }

        // Copy rest of firmware
        memcpy(temp_buf, initial_data + (i * FLASH_PAGESIZE), rem_fw_bytes);
        // Copy what will fit of the release message
        memcpy(temp_buf + rem_fw_bytes, initial_msg, msg_len - rem_msg_bytes);
        // Program the final firmware and first part of the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), temp_buf, rem_fw_bytes + (msg_len - rem_msg_bytes));

        // If there are more bytes, program them directly from the release message string
        if (rem_msg_bytes > 0){
            // Writing to a new page. Increment pointer
            i++;
            program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)(initial_msg + (msg_len - rem_msg_bytes)), rem_msg_bytes);
        }
    }
}

/* ****************************************************************
 *
 * Reads and decrypts a packet.
 *
 * \param arr is the array that unencrypted data will be written to.
 * 
 * \return Returns a 0 on success, or a 1 if the GHASH was invalid.
 * 
 * ****************************************************************
 */
int frame_decrypt(uint8_t *arr){
    // Misc vars for reading
    int read = 0;
    uint32_t rcv = 0;

    // Packet components: each is 16 bytes
    // The data array is not declared here, as it is a parameter
    uint8_t tag[16];
    uint8_t nonce[16];

    // Reads the packet
    for (int i = 0; i < 16; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        arr[i] = rcv;
    }
    for (int i = 0; i < 16; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        tag[i] = rcv;
    }
    for (int i = 0; i < 16; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        nonce[i] = rcv;
    }

    /*
    for (int i = 0; i < 1024; i += 1) {
        backup[i] = complete_data[i];
    }*/

    // Initialize the GCM, with counter and GHASH
    br_aes_ct_ctr_keys counter;
    br_gcm_context context;
    br_aes_ct_ctr_init(&counter, KEY, 16); // Note: KEY is a macro in keys.h
    br_gcm_init(&context, &counter.vtable, br_ghash_ctmul32);

    // Add nonce and header
    br_gcm_reset(&context, nonce, 16);
    br_gcm_aad_inject(&context, HEADER, 16); // HEADER is also a macro in keys.h
    br_gcm_flip(&context);

    // Decrypt data
    br_gcm_run(&context, 0, arr, 16);

    /*for (int i = 0; i < 1024; i += 1) {
        complete_data[i] = backup[i];
    }
    */

    // Check GHASH
    if (br_gcm_check_tag(&context, tag)) {
        return 0;
    } else {
        return 1;
    }
}

/* ****************************************************************
 *
 * Recieves and decrypts all frames using frame_decrypt()
 * 
 * Writes start firmware metadata, firmware data, and release message
 * to flash
 * 
 * ****************************************************************
 */
void load_firmware(void){
    uart_write_str(UART2, "\nUpdate started\n");

    uint8_t chunk_arr[16];   // Stores 1 packet, and is overwritten every decrypt
    uint8_t type = 0;
    int error = 0;              // stores frame_decrypt return
    int error_counter = 0;

    uint32_t data_index = 0;            // Length of current data chunk written to flash
    uint32_t page_addr = FW_BASE;   // Address to write to in flash

    // variables to store data from START frame
    uint16_t version;
    uint16_t f_size;
    uint16_t r_size;

    // ************************************************************
    // Read START frame and checks for errors
    do {
        // Read frame
        int read = 0;
        uint8_t rcv = 0;

        unsigned char gen_hash[32];
        unsigned char tag[32];

        type = uart_read(UART1, BLOCKING, &read);     // Message Type
        for (int i = 0; i < 1024; i += 1) { // Data
            rcv = uart_read(UART1, BLOCKING, &read);
            complete_data[i] = rcv;
        }
        for (int i = 0; i < 32; i += 1) {             // Tag
            rcv = uart_read(UART1, BLOCKING, &read);
            tag[i] = rcv;
        }

        // nl(UART2);
        uart_write_hex_bytes(UART2, complete_data, FLASH_PAGESIZE);
        nl(UART2);
        uart_write_hex_bytes(UART2, tag , 32);

        sha_hash(complete_data, 1024, gen_hash);
        nl(UART2);
        uart_write_hex_bytes(UART2, gen_hash, 32);
        nl(UART2);

        if (gen_hash == tag) {
            uart_write(UART1, TYPE);
            uart_write(UART1, OK);
        } else {
            uart_write(UART1, TYPE);
            uart_write(UART1, END);
        }

        return;

        // Get version (0x2)
        version = (uint16_t)chunk_arr[1];
        version |= (uint16_t)chunk_arr[2] << 8;
        uart_write_str(UART2, "Received Firmware Version: ");
        uart_write_hex(UART2, version);
        nl(UART2);
        // Get release message size in bytes (0x2)
        r_size = (uint16_t)chunk_arr[5];
        r_size |= (uint16_t)chunk_arr[6] << 8;
        uart_write_str(UART2, "Received Release Message Size: ");
        uart_write_hex(UART2, r_size);
        nl(UART2);
        // Get firmware size in bytes (0x2) 
        f_size = (uint16_t)chunk_arr[3];
        f_size |= (uint16_t)chunk_arr[4] << 8;
        uart_write_str(UART2, "Received Firmware Size: ");
        uart_write_hex(UART2, f_size);
        nl(UART2);

        // Get version metadata
        uint16_t old_version = *fw_version_address;
        // If version 0 (debug), don't change version
        // Halp! doesn't get 0'd when writing
        if (version == 0){
            version = old_version;
        }

        // Check for GHASH error
        if (error == 1){
            uart_write_str(UART2, "Incorrect GHASH\n");
        // Check for incorrect message type
        } else if (chunk_arr[0] != 1){
            uart_write_str(UART2, "Incorrect Message Type\n");
            error = 1;
        // If version less than old version, reject and reset
        } else if ((version < old_version)){
            uart_write_str(UART2, "Incorrect Version\n");
            error = 1;
        }

        // Reject metadata if any error
        if (error == 1){
            uart_write(UART1, TYPE);
            uart_write(UART1, ERROR);
        }

        // Implements error timeout
        // If 10+ errors for a single frame, end by returning out of method
        error_counter += error;
        if (error_counter > 10) {
            uart_write_str(UART2, "Timeout: too many errors\n");
            uart_write(UART1, TYPE);
            uart_write(UART1, END);
            SysCtlReset();
            return;
        }
    } while (error != 0);

    // Resets counter, since start frame successful
    error_counter = 0;

    // Write metadata to flash (firmware size and version) 
    // Version is at lower address, size is at higher address
    uint32_t metadata = ((f_size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    // Acknowledge the metadata.
    uart_write_str(UART2, "Metadata written to flash\n");
    uart_write(UART1, TYPE);
    uart_write(UART1, OK);

    // ************************************************************
    // Process DATA frames
    for (int i = 0; i < f_size; i += 15){
        // Reading and checking for errors
        do {
            // Read frames
            int read = 0;
            for (int i = 0; i < 16; i += 1) {
                chunk_arr[i] = uart_read(UART1, BLOCKING, &read);
            }

            // Error handling
            if (error == 1){
                uart_write_str(UART2, "Incorrect GHASH\n");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
            }else if (chunk_arr[0] != 2){
                uart_write_str(UART2, "Incorrect Message Type\n");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            }

            // Error timeout implementation
            error_counter += error;
            if(error_counter > 10){
                uart_write_str(UART2, "Timeout: too many errors\n");
                uart_write(UART1, TYPE);
                uart_write(UART1, END);
                SysCtlReset();
                return;
            }

        } while (error != 0);

        // Write that packet has been recieved
        uart_write_str(UART2, "Recieved bytes at ");
        uart_write_hex(UART2, i);
        nl(UART2);

        // Writing to flash
        for (int j = 1; j < 16; j++) {
            // Get the data that will be written
            if (f_size - (i + j) >= 0) {
                complete_data[data_index] = chunk_arr[j];
                data_index += 1;
            }
            
            // If page is filled up, write to flash
            // Note: also has to check for padding when flashing release message
            if (data_index >= FLASH_PAGESIZE) {
                uart_write_hex_bytes(UART2, complete_data, 1024);

                // Check for errors while writing to flash
                do {
                    // Write to flash, then check if data and memory match
                    if (program_flash(page_addr, complete_data, data_index) == -1){
                        uart_write_str(UART2, "Error while writing\n");
                        uart_write(UART1, TYPE);
                        uart_write(UART1, ERROR);
                        error = 1;
                    } else if (memcmp(complete_data, (void *) page_addr, data_index) != 0){
                        uart_write_str(UART2, "Error while writing\n");
                        uart_write(UART1, TYPE);
                        uart_write(UART1, ERROR);
                        error = 1;
                    }
                    
                    // Error timeout
                    error_counter += error;
                    if (error_counter > 10){
                        uart_write_str(UART2, "Timeout: too many errors\n");
                        uart_write(UART1, TYPE);
                        uart_write(UART1, END);
                        SysCtlReset();
                        return;
                    }
                } while(error != 0);
                
                // Write success and debugging messages to UART2.
                uart_write_str(UART2, "Page successfully programmed\nAddress: ");
                uart_write_hex(UART2, page_addr);
                uart_write_str(UART2, "\nBytes: ");
                uart_write_hex(UART2, data_index);
                nl(UART2);

                // Update to next page
                page_addr += FLASH_PAGESIZE;
                data_index = 0;
            }
        }

        // Send packet recieved success message
        uart_write(UART1, TYPE);
        uart_write(UART1, OK);

        // Reset counter inbetween packets
        error_counter = 0;
    }

    // ************************************************************
    // Process RELEASE MESSAGE frames
    for (int i = 0; i < r_size; i += 15){
        // Read and check for errors
        do{
            // Read frames
            int read = 0;
            for (int i = 0; i < 16; i += 1) {
                chunk_arr[i] = uart_read(UART1, BLOCKING, &read);
            }

            // Check for errors
            if (error == 1){
                uart_write_str(UART2, "Incorrect GHASH\n");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
            } else if (chunk_arr[0] != 2){
                uart_write_str(UART2, "Incorrect Message Type\n");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            }

            // Error timeout
            error_counter += error;
            if (error_counter > 10) {
                uart_write_str(UART2, "Timeout: too many errors\n");
                uart_write(UART1, TYPE);
                uart_write(UART1, END);
                SysCtlReset();
                return;
            }
        } while (error != 0);

         // Write that packet has been recieved
        uart_write_str(UART2, "Recieved bytes at ");
        uart_write_hex(UART2, i);
        nl(UART2);

        // Writing to flash
        for (int j = 1; j < 16; j++) {
            // Get the data that will be written
            if (r_size - (i + j) >= 0) {
                complete_data[data_index] = chunk_arr[j];
                data_index += 1;
            }

            // If page is filled up or at end of release message, write to flash
            if ((data_index >= FLASH_PAGESIZE - 1) || (r_size - i == j)) {
                uart_write_hex_bytes(UART2, complete_data, 1024);

                // Check for errors while writing to flash
                do {
                    // Write to flash, then check if data and memory match
                    if (program_flash(page_addr, complete_data, data_index) == -1){
                        uart_write_str(UART2, "Error while writing\n");
                        uart_write(UART1, TYPE);
                        uart_write(UART1, ERROR);
                        error = 1;
                    } else if (memcmp(complete_data, (void *) page_addr, data_index) != 0){
                        uart_write_str(UART2, "Error while writing\n");
                        uart_write(UART1, TYPE);
                        uart_write(UART1, ERROR);
                        error = 1;
                    }
                    
                    // Error timeout
                    error_counter += error;
                    if (error_counter > 10){
                        uart_write_str(UART2, "Timeout: too many errors\n");
                        uart_write(UART1, TYPE);
                        uart_write(UART1, END);
                        SysCtlReset();
                        return;
                    }
                } while(error != 0);
                
                // Write success and debugging messages to UART2.
                uart_write_str(UART2, "Page successfully programmed\nAddress: ");
                uart_write_hex(UART2, page_addr);
                uart_write_str(UART2, "\nBytes: ");
                uart_write_hex(UART2, data_index);
                nl(UART2);

                // Update to next page
                page_addr += FLASH_PAGESIZE;
                data_index = 0;
            }
        }

        // Send packet recieved success message
        uart_write(UART1, TYPE);
        uart_write(UART1, OK);

        // Reset counter inbetween packets
        error_counter = 0;
    }

    // ************************************************************
    // Process END frame
    do {
        // Read frame
        int read = 0;
        for (int i = 0; i < 16; i += 1) {
            chunk_arr[i] = uart_read(UART1, BLOCKING, &read);
        }

        // Check for errors
        if (error == 1){
            uart_write_str(UART2, "Incorrect GHASH\n");
            uart_write(UART1, TYPE);
            uart_write(UART1, ERROR);
        } else if (chunk_arr[0] != 3){
            uart_write_str(UART2, "Incorrect Message Type\n");
            uart_write(UART1, TYPE);
            uart_write(UART1, ERROR);
            error = 1;
        }

        // Error timeout
        error_counter += error;
        if (error_counter > 10) {
            uart_write_str(UART2, "Timeout: too many errors\n");
            uart_write(UART1, TYPE);
            uart_write(UART1, END);
            SysCtlReset();
            return;
        }

    } while (error != 0);

    uart_write_str(UART2, "End frame processed\n\n(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧\n");

    // End return
    uart_write(UART1, TYPE);
    uart_write(UART1, OK);
    
    uart_write_str(UART2, "Received Firmware Version: ");
    uart_write_hex(UART2, version);
    uart_write_str(UART2, "Received Release Message Size: ");
    uart_write_hex(UART2, r_size);
    uart_write_str(UART2, "Received Firmware Size: ");
    uart_write_hex(UART2, f_size);
    return;
}

/* ****************************************************************
 *
 * Programs a stream of bytes to the flash.
 * Also performs an erase of the specified flash page before writing
 * the data.
 * 
 * \param page_addr is the starting address of a 1KB page. Must be 
 * a multiple of four
 * \param data is a pointer to the data to write.
 * \param data_len is the number of bytes to write.
 * 
 * \return Returns 0 on success, or -1 if an error is encountered
 *
 * ****************************************************************
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len){
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase(page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE){
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
        if (ret != 0){
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++){
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++){
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, page_addr + num_full_bytes, 4);
    }else{
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, page_addr, data_len);
    }
}

/* ****************************************************************
 *
 * Boots firmware (when response is 'B')
 * 
 * ****************************************************************
 */
void boot_firmware(void){
    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART2, (char *)fw_release_message_address);

    // Boot the firmware
    __asm(
        "LDR R0,=0x10001\n\t"
        "BX R0\n\t");
}

/* ****************************************************************
 *
 * Writes to the UART in hex format.
 * 
 * \param uart is the UART that will be written to. Valid UARTs are
 * UART0, UART1, and UART2.
 * \param start is a pointer to the data to be written to UART
 * \param len is the length of the data that will be written in bytes
 * 
 * ****************************************************************
 */
void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';
        
        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}