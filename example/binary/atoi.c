#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    char buf[10];
    read(0, buf, 10);
    int length = atoi(buf);
    if (length > 0x51 && length < 0x60){
    	read(0, buf, length);
    }
    return 0;
}
