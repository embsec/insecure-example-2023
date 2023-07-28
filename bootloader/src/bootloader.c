// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

/*
Bootloader for Stellaris
recieves and processes frames from firmware update and stores them to flash 

TODO: 
write message frames to flash: line 479
delete while loop that used to check flash error: line 485

*/

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
#include <bearssl_aead.h>   // Takes less than bearssl.h

// Application Imports
#include "uart.h"
#include "../keys.h"

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
// Note: first byte is message type, second is error type
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
unsigned char data[FLASH_PAGESIZE];

/*
 * 1. intilializes UARTS
 * 2. calls functions to load firmware
 * --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

/*
 * Load initial firmware into flash V2
 *  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

/*
 * ABSTRACTED function for receiving data frames when needed
 * Reads and decrypts a packet
 * Takes a uint8_t array with 16+ items. Deciphered data is written to the array
 * Returns an int, which is 0 if the GHASH matches and 1 if it does not
 * GCM Reference: https://bearssl.org/apidoc/structbr__gcm__context.html
 * --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 */
int frame_decrypt(uint8_t *arr){
    uart_write_str(UART2, "\nDecrypt started\n");
    // Misc vars for reading
    int read = 0;
    uint32_t rcv = 0;

    // Init packet parts: each is 16 bytes
    uint8_t data[16];
    uint8_t tag[16];
    uint8_t nonce[16];

    // Read packet
    for (int i = 0; i < 16; i += 1) {
        // Note: uart_read only reads 1 byte @ a time
        //Note: data includes message as first byte
        rcv = uart_read(UART1, BLOCKING, &read);
        data[i] = rcv;
    }
    for (int i = 0; i < 16; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        tag[i] = rcv;
    }
    for (int i = 0; i < 16; i += 1) {
        rcv = uart_read(UART1, BLOCKING, &read);
        nonce[i] = rcv;
    }

    uart_write_str(UART2, "Packet recieved\n");

    // Initialize GCM, with counter and GHASH
    // Note: KEY should be a macro in keys.h
    br_aes_ct_ctr_keys counter;
    br_gcm_context context;
    br_aes_ct_ctr_init(&counter, KEY, 16);
    br_gcm_init(&context, &counter.vtable, br_ghash_ctmul32);

    // Add nonce and header
    // Note: HEADER is also a macro in keys.h
    br_gcm_reset(&context, nonce, 16);
    br_gcm_aad_inject(&context, HEADER, 16);
    br_gcm_flip(&context);

    // Decrypt data
    br_gcm_run(&context, 0, data, 16);

/*int gcm_decrypt_and_verify(char* key, char* iv, char* ct, int ct_len, char* aad, int aad_len, char* tag) {
    br_aes_ct_ctr_keys bc;
    br_gcm_context gc;
    br_aes_ct_ctr_init(&bc, key, 16);
    br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);

    br_gcm_reset(&gc, iv, 16);         
    br_gcm_aad_inject(&gc, aad, aad_len);    
    br_gcm_flip(&gc);                        
    br_gcm_run(&gc, 0, ct, ct_len);   
    if (br_gcm_check_tag(&gc, tag)) {
        return 1;
    }
    return 0; 
}*/

    // Add data to arr, then return if everything's ok
    for (int i = 0; i < 16; i += 1) {
        arr[i] = data[i];
    }

    uart_write_str(UART2, "Decrypt done\n");

    // Check tag
    if (br_gcm_check_tag(&context, tag)) {
        return 0;
    } else {
        return 1;
    }
}

/*
 * 1. recieves and decrypts all frames using frame_decrypt
 * 2. writes start frame version and firmware size, data, and message to flash
 * --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 */
void load_firmware(void){
    uart_write_str(UART2, "Load started\n");

    uint8_t data_arr[16];   // Stores 1 packet, and is overwritten every decrypt
    int error;              // stores frame_decrypt return
    int error_counter = 0;

    uint32_t data_index;            // Length of current data chunk written to flash
    uint32_t page_addr = FW_BASE;   // Address to write to in flash

    // variables to store data from START frame
    uint16_t version;
    uint16_t f_size;
    uint16_t r_size;

   // read and process and flash START frame ONLY
   //**********************************************************************************************************************
    do {
        error = frame_decrypt(data_arr);

        // Get version (0x2)
        version = (uint16_t)data_arr[1];
        version |= (uint16_t)data_arr[2] << 8;
        uart_write_str(UART2, "Received Firmware Version: ");
        uart_write_hex(UART2, version);
        nl(UART2);
        // Get release message size in bytes (0x2)
        r_size = (uint16_t)data_arr[5];
        r_size |= (uint16_t)data_arr[6] << 8;
        uart_write_str(UART2, "Received Release Message Size: ");
        uart_write_hex(UART2, r_size);
        nl(UART2);
        // Get firmware size in bytes (0x2) 
        f_size = (uint16_t)data_arr[3];
        f_size |= (uint16_t)data_arr[4] << 8;
        uart_write_str(UART2, "Received Firmware Size: ");
        uart_write_hex(UART2, f_size);
        nl(UART2);

        // Set up version compare
        uint16_t old_version = *fw_version_address;
        // If version 0 (debug), don't change version
        if (version == 0){
            version = old_version;
        }

        // Check for errors
        if (error == 1){
            uart_write_str(UART2, "Incorrect GHASH\n");
        } else if (data_arr[0] != 1){
            uart_write_str(UART2, "Incorrect Message Type\n");
            error = 1;
        // If version less than old version, reject and reset
        } else if ((version < old_version)){
            uart_write_str(UART2, "Incorrect Version\n");
            error = 1;
        }

        if (error == 1){
            // Reject metadata
            uart_write(UART1, TYPE);
            uart_write(UART1, ERROR);
            uart_write_str(UART2, "Error sent\n");
        }

        // If there was an error, error_counter increases 1
        // If error counter is too high, end (by returning out of main)
        error_counter += error;
        if (error_counter > 10) {
            uart_write_str(UART2, "Too many bad frames");
            uart_write(UART1, TYPE);
            uart_write(UART1, END);
            SysCtlReset();
            return;
        }
    } while (error != 0);
    // reading START frame FINISHED

    // Resets counter, since start frame successful
    error_counter = 0;

    // FLASH data from start frame (firmware size and version) 
    // Version is at lower address, size is at higher address
    uint32_t metadata = ((f_size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    // Acknowledge the metadata.
    uart_write_str(UART2, "Metadata written to flash");
    uart_write(UART1, TYPE);
    uart_write(UART1, OK);

    // read and process and flash DATA frames
    //**********************************************************************************************************************
    for (int i = 0; i < f_size; i += 15){
        do {
            error = frame_decrypt(data_arr);

            // Error handling
            if (error == 1){
                uart_write_str(UART2, "error decrypting data array");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
            }else if (data_arr[0] != 2){
                uart_write_str(UART2, "Incorrect Message Type");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            }
            //increase error counter if there was an error
            error_counter += error;

            // Error timeout if too many errors
            if(error_counter > 10){
                uart_write_str(UART2, "Too much error. Restarting...");
                uart_write(UART1, TYPE);
                uart_write(UART1, END);
                SysCtlReset();
                return;
            }

        } while (error != 0);

        // Write that full packet has been recieved
        uart_write_str(UART2, "Successfully recieved data\ndata: ");
        uart_write_hex(UART2, i);

        // isolate only data from data_arr
        uint8_t message[15];
        for (int j = 0; j < 15; j++) {
            message[i] = data_arr[i+1];
        }

        // Whrites to flash
        // Checks if last frame is padded, and if so, change the size argument accordingly for writing to flash
        if (f_size - i < 15) {
            data_index = f_size - i;
        } else {
            data_index = 15;
        }

        // Check for errors while writing to flash
        do {
            if(program_flash(page_addr, message, data_index)){
                uart_write_str(UART2, "Error while writing");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            } else if (memcmp(message, (void *) page_addr, data_index) != 0){
                uart_write_str(UART2, "Error while writing");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            }

            error_counter += error;
    
            // Error timeout
            if(error_counter > 10){
                uart_write_str(UART2, "Too much error. Restarting...");
                uart_write(UART1, TYPE);
                uart_write(UART1, END);
                SysCtlReset();
                return;
            }
            
        } while(error != 0);
        
        error_counter = 0;

        // Write success and debugging messages to UART2.
        uart_write_str(UART2, "Page successfully programmed\nAddress: ");
        uart_write_hex(UART2, page_addr);
        uart_write_str(UART2, "\nBytes: ");
        uart_write_hex(UART2, data_index);
        nl(UART2);

        // Update to next page
        page_addr += 15;

        uart_write_str(UART2, "Packet written.");
        uart_write(UART1, TYPE);
        uart_write(UART1, OK);
    }

    //reset counter
    error_counter = 0;

    // read and process and flash RELEASE MESSAGE frames
    //**********************************************************************************************************************
    for (int i = 0; i < r_size; i += 15){
        // reads and checks for errors
        do{
            error = frame_decrypt(data_arr);

            // check for wrong hash ot message type, error accordingly
            if (error == 1){
                uart_write_str(UART2, "Incorrect GHASH");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
            } else if (data_arr[0] != 2){
                uart_write_str(UART2, "Incorrect Message Type");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            }

            // check if too many errors, error accordingly
            error_counter += error;
            if (error_counter > 10) {
                uart_write_str(UART2, "Too many bad frames");
                uart_write(UART1, TYPE);
                uart_write(UART1, END);
                SysCtlReset();
                return;
            }
        } while (error != 0);

        // insert write to flash below
         // Write that full packet has been recieved
        uart_write_str(UART2, "Successfully recieved data\ndata: ");
        uart_write_hex(UART2, i);

        // isolate only data from data_arr
        uint8_t message[15];
        for (int j = 0; j < 15; j++) {
            message[i] = data_arr[i+1];
        }

        // Whrites to flash
        // Checks if last frame is padded, and if so, change the size argument accordingly for writing to flash
        if (r_size - i < 15) {
            data_index = r_size - i;
        } else {
            data_index = 15;
        }

        // Check for errors while writing to flash
        do {
            if(program_flash(page_addr, message, data_index)){
                uart_write_str(UART2, "Error while writing");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            } else if (memcmp(message, (void *) page_addr, data_index) != 0){
                uart_write_str(UART2, "Error while writing");
                uart_write(UART1, TYPE);
                uart_write(UART1, ERROR);
                error = 1;
            }

            error_counter += error;
    
            // Error timeout
            if(error_counter > 10){
                uart_write_str(UART2, "Too much error. Restarting...");
                uart_write(UART1, TYPE);
                uart_write(UART1, END);
                SysCtlReset();
                return;
            }
            
        } while(error != 0);
        
        error_counter = 0;

        // Write success and debugging messages to UART2.
        uart_write_str(UART2, "Page successfully programmed\nAddress: ");
        uart_write_hex(UART2, page_addr);
        uart_write_str(UART2, "\nBytes: ");
        uart_write_hex(UART2, data_index);
        nl(UART2);

        // Update to next page
        page_addr += 15;

        uart_write_str(UART2, "Packet written.");
        uart_write(UART1, TYPE);
        uart_write(UART1, OK);
    }

    // read and process and flash END FRAME
    //**********************************************************************************************************************
    do {
        // read
        error = frame_decrypt(data_arr);

        // check for wrong hash ot message type, error accordingly
        if (error == 1){
            uart_write_str(UART2, "Incorrect GHASH");
            uart_write(UART1, TYPE);
            uart_write(UART1, ERROR);
        } else if (data_arr[0] != 3){
            uart_write_str(UART2, "Incorrect Message Type");
            uart_write(UART1, TYPE);
            uart_write(UART1, ERROR);
            error = 1;
        }

        // Check if too many errors, error accordingly
        error_counter += error;
        if (error_counter > 10) {
            uart_write_str(UART2, "Too many bad frames");
            uart_write(UART1, TYPE);
            uart_write(UART1, END);
            SysCtlReset();
            return;
        }

    } while (error != 0);
    // end debug message
    uart_write_str(UART2, "All frames processed");
    uart_write(UART1, TYPE);
    uart_write(UART1, OK); // acknowledge the frame.
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 * --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

// Boots firmware (when response is 'B')
//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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