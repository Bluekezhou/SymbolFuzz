/*
 * Created by Bluecake 2018-11-9
 * This C program is a signature source file. Building this source file with option "-static" 
 * will create a signature elf file which can be used for static compiled function recognition.
 *
 * How to work?
 *     When compiled with "-static" option, library function implemention will be linked into   
 * the program. So, we can create a model program and extract library function information from
 * it. Of course, we should call more library function as posssible as we can.
 *
 * How to compile?
 *     If you want to compile a 32bit program, run the following command:
 *         gcc -o signature signature.c -m32 -static
 *     If you want to compile a 64bit program, run the following command:
 *         gcc -o signature signature.c -static
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    char buf[100];
    int tmp_int;

    // memory related library function
    char *ptr = malloc(0x20);
    free(ptr);

    // format functions 
    printf("this is a test");
    sprintf(buf, "this is a test %d", 1);

    // IO related functions
    gets(buf);
    scanf("%s", buf);

    //header <unistd.h>
    tmp_int = atoi("234");
    return 0;
}
