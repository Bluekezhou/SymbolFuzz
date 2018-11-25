#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main()
{
    char buf[20];
    read(0, buf, 20);
    if (*(int*)buf != 0x31363235)
        return 0;

    char more[10];
    read(0, more, 10);
    if (strcmp(more, "level 2") != 0)
        return 0;

    int length = atoi(buf + sizeof(int));
    if (length > 0x90 && length < 0x100){
    	read(0, buf, length);
    }
    return 0;
}