#include <stdio.h>
#include <unistd.h>

int main()
{
    char s[100];
    read(0, s, 100);
    printf("s is %s", s);
    return 0;
}
