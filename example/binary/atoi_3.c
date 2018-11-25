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
  
    char buf2[10];
    int i=0;
    for (i=0; i<10 && buf[i]; i++){
        buf2[i] = buf[i];
	    buf2[i] ^=0xff;
	    buf2[i] -=1;
    }
   
    int length = atoi(buf2 + sizeof(int));
    if (length > 0x90 && length < 0x100){
    	read(0, buf, length);
    }
    return 0;
}
