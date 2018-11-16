#include <string.h>

#define SEARCH_START 0
#define NUM_START 1

int isNumericChar(char x){
    return (x >= '0' && x <= '9')? 1: 0;
}

int atoi_hook(char *buf){
    int i=0;
    int result = 0;
    int sign = 1;
    while(buf[i] == ' ') i++;
    if (buf[i] == '-'){
        sign = -1;
        i++;
    }
    else if (buf[i] == '+') {
        i++;
    }

    int j=i;
    while(isNumericChar(buf[j])){
        if (j-i > 10)
            return -1;
        result = 10 * result + buf[i] - '0';
    }
    return result * sign;
}

int main(){
    // printf("atoi(\"-1AAAAA\") = %d\n", atoi("-1AAAAA"));
    return 0;
}