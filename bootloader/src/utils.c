

/*
****************************************************************
* Takes in a number of bytes to read, a UART to read them from, 
* and a blocking value and a destination to write them to
* Returns 0 if reading the whole thing went successfully
* Returns a 1 if otherwise
****************************************************************
*/
int uart_read_bytes(int bytes, int uart, int blocking, uint8_t dest[]){
    int rcv = 0;//Received data
    int read = 0; //Flag that reports on success of read operation
    int result = 0;//Stores operation status
    for (int i = 0; i < bytes; i += 1) {
        rcv = uart_read(uart, blocking, &read);
        dest[i] = rcv;
        if (read != 0){
            result = 1;
        }
    }
    return result;
}