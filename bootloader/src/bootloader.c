// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

/*
TODO: 
- Eleanor : 
-connect key for decrypting 

- Reina:
- process/decrypt the data  - in progress
- check message type for data packets (in frame decrypt) - unfinished
- write data to flash - in progress

- Shivika and Caroline : 
- write start and end frame to flash (?) - unfinished
- write message to flash, and then delete - unfinished
- 
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
// Note: first byte is message type
#define OK ((unsigned char)0x40)
#define ERROR ((unsigned char)0x41)
#define END ((unsigned char)0x42)
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

    uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
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
 * Load initial firmware into flash (V2)
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
 * Reads and decrypts a packet
 * Takes a uint8_t array with 16+ items. Deciphered data is written to the array
 * Returns an int, which is 0 if the GHASH matches and 1 if it does not
 * GCM Reference: https://bearssl.org/apidoc/structbr__gcm__context.html
 */
int frame_decrypt(uint8_t *arr){
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

    // Initialize GCM, with counter and GHASH
    // Note: KEY should be a macro in keys.h
    br_block_ctr_class counter = { &counter, &KEY, 16};
    br_ghash ghash;
    br_gcm_context context;
    br_gcm_init(&context, &counter, ghash);
    br_gcm_reset(&context, nonce, 16);

    // Add header data
    // Note: HEADER is also a macro in keys.h
    br_gcm_aad_inject(&context, &HEADER, 16);
    br_gcm_flip(&context);

    // Decrypt data
    br_gcm_run(&context, 0, data, 16);

    // Add data to arr, then return if everything's ok
    for (int i = 0; i < 16; i += 1) {
        arr[i] = data[i];
    }

    // Check tag
    if (br_gcm_check_tag(&context, tag)) {
        return 0;
    } else {
        return 1;
    }
}

/*
 * Load the firmware into flash.
 */
void load_firmware(void){
    int frame_length = 0;
    int read = 0;
    uint32_t rcv = 0; // This and read should be not here soon

    // Used to read check for error
    uint8_t data_arr[16];
    int error;
    int error_counter = 0;

    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;
    uint8_t msg_type = 5;

    // 1st frame data
    uint16_t message_type = 0;
    uint16_t version = 0;
    uint16_t f_size = 0;
    uint16_t r_size = 0;

    // Read first packet ONLY
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
            uart_write_str(UART2, "Incorrect GHASH");
            // Reject the metadata.
            uart_write(UART1, ERROR);
        } else if (data_arr[0] != 1){
            uart_write_str(UART2, "Incorrect Message Type");
            // Reject the metadata.
            uart_write(UART1, ERROR);
            error = 1;
        // If version less than old version, reject and reset
        } else if (version <= old_version){
            uart_write_str(UART2, "Incorrect Version");
            uart_write(UART1, ERROR);
            error = 1;
        }

        // If there was an error, error_counter increases 1
        // If error counter is too high, end (by returning out of main)
        error_counter += error;
        if (error_counter > 10) {
            uart_write_str(UART2, "Too many bad packets");
            uart_write(UART1, END);
            SysCtlReset();
            return;
        }
    } while (error != 0);
    
    // Resets counter, since first frame successful
    error_counter = 0;

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((f_size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART1, OK); // Acknowledge the metadata.


    /* Loop here until you can get all your characters and stuff (data frames) 
        take data from array, check message type, put in flash
    */
    
    //retrieve message type 0xf
    /*two loops
    one for firmware
    -   loop until it reads the data packets (done)
    -   while loop has frame length amount of frames for the firmware (done)
    -   succcessful packet = deincrements firm thing breaks (done)
    one for release message
    -   to be done soon
    delete this portion after success
    */

    // firmware data 0xf
    for (int i = 0; i < f_size; i += 16){
        do {
            error = frame_decrypt(data_arr);
            if (error == 1){
                uart_write_str(UART2, "error decrypting data array");
            }else if (data_arr[0] != 3){
                uart_write_str(UART2, "incorrect data type");

            }

            error_counter += error;
            if(error_counter > 5){
                uart_write_str(UART2, "Too much error. Restarting...");
                uart_write(UART1, END);
                SysCtlReset();

            //saving data
            if(error == 0){
                //store i into UART and write to flash
                uart_write_str(UART2, "Successfully sent data\ndata: ");
                uart_write_hex(UART2, error);

                //splitting message type and raw data
                uint32_t message_type = (data_arr[i] & 0x8000) >> 15; // the 1 bit is message_type
                uint32_t raw_data = data_arr[i] & 0x7FFF; // the rest (aka 15 bits) are the raw_data

                //it's split and now it's intended to be stored separately for eternity?
                uint_t message_type_and_raw_data[2];
                message_type_and_raw_data[0];
                message_type_and_raw_data[1];

                //uint32_t data_arr = ((f_size & 0xFFFF) << 16) | (version & 0xFFFF); << I commented it out just incase we arent supposed to split em separately for eternity
                program_flash(message_type_and_raw_data, (uint8_t*)(&message_type_and_raw_data), 4);
                uart_write(UART1, OK);
                return 0;
            }
            }

        } while (error != 0);

    }

    // Release message packets
    for (int i = 0; i < r_size; i += 15){
        // Reads and checks for errors
        do{
            error = frame_decrypt(data_arr);

            // Error handling
            if (error == 1){
                uart_write_str(UART2, "Incorrect GHASH");
                uart_write(UART1, ERROR);
            } else if (data_arr[0] != 2){
                uart_write_str(UART2, "Incorrect Message Type");
                uart_write(UART1, ERROR);
                error = 1;
            }

            // Check if too many errors
            error_counter += error;
            if (error_counter > 10) {
                uart_write_str(UART2, "Too many bad packets");
                uart_write(UART1, END);
                SysCtlReset();
                return;
            }
        } while (error != 0);
        
        // Reset counter after success
        error_counter = 0;

        // Insert write to flash below
        // Remember: data being written is data_arr[1] --> data_arr[15]
    }

    /* Loop here until you can get all your characters and stuff */
    while (1){

        // Get two bytes for the length.
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART1, BLOCKING, &read);
        frame_length += (int)rcv;

        // Get the number of bytes specified
        for (int i = 0; i < frame_length; ++i){
            data[data_index] = uart_read(UART1, BLOCKING, &read);
            data_index += 1;
        } // for

        // If we filed our page buffer, program it
        if (data_index == FLASH_PAGESIZE || frame_length == 0){

            if(frame_length == 0){
                uart_write_str(UART2, "Got zero length frame.\n");
            }
            
            // Try to write flash and check for error
            if (program_flash(page_addr, data, data_index)){
                uart_write(UART1, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Verify flash program
            if (memcmp(data, (void *) page_addr, data_index) != 0){
                uart_write_str(UART2, "Flash check failed.\n");
                uart_write(UART1, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Write debugging messages to UART2.
            uart_write_str(UART2, "Page successfully programmed\nAddress: ");
            uart_write_hex(UART2, page_addr);
            uart_write_str(UART2, "\nBytes: ");
            uart_write_hex(UART2, data_index);
            nl(UART2);

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // If at end of firmware, go to main
            if (frame_length == 0){
                uart_write(UART1, OK);
                break;
            }
        } // if

        uart_write(UART1, OK); // Acknowledge the frame.
    }                          // while(1)

    // End frame starts here
    do {
        // Read
        error = frame_decrypt(data_arr);

        // Error handling
        if (error == 1){
            uart_write_str(UART2, "Incorrect GHASH");
            uart_write(UART1, ERROR);
        } else if (data_arr[0] != 3){
            uart_write_str(UART2, "Incorrect Message Type");
            uart_write(UART1, ERROR);
            error = 1;
        }

        // Check if too many errors
        error_counter += error;
        if (error_counter > 10) {
            uart_write_str(UART2, "Too many bad packets");
            uart_write(UART1, END);
            SysCtlReset();
            return;
        }

    } while (error != 0);
    // End debug message
    uart_write_str(UART2, "All packets processed");
    uart_write(UART1, OK); // Acknowledge the frame.
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
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