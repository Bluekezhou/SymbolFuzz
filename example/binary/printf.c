#include <stdio.h>
#include <unistd.h>

int main()
{
    setbuf(stdout, 0);
    char format[100], buf[100];
    printf("input format: ");
    read(0, format, 100);
    printf("input buffer: ");
    read(0, buf, 100);
    printf(format, buf);
}
