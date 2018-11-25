#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    char buf[10];
    read(0, buf, 10);
    int length = atoi(buf);
    if (length < 0 || length > 20)
        exit(0);

    char buffer[100];
    read(0, buffer, length);
    if(strcmp(buffer, "strlen is easy") == 0)
    {
        printf("Woo !!!");
        read(0, buf, 1024); 
    }
    return 0;
}
