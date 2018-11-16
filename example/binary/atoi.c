#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    char buf[100];
    read(0, buf, 10);
    int length = atoi(buf);
    if (length > 0x100){
    	read(0, buf, length);
    }
    return 0;
}
