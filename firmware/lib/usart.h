#define USART_BAUDRATE 115200
#define BAUD_PRESCALE (((F_CPU / (USART_BAUDRATE * 16UL))) - 1)

int readLine(char* buffer, int max_bytes);
void write(const char *buffer);
void writeLine(const char* buffer);
void initializeUSART(void);
