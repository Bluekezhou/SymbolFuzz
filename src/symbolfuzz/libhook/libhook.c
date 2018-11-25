#include <stdio.h>
#include <string.h>

#define SEARCH_START 0
#define NUM_START 1

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
    while(buf[j] >= '0' && buf[j] <= '9'){
        if (j-i > 10)
            return -1;
        result = 10 * result + buf[j] - '0';
        j++;
    }
    return result * sign;
}

int strcmp_hook(char *s1, char *s2){
    int i=0;
    while(s1[i]){
        if (s1[i] < s2[i])
            return -1;
        else if (s1[i] > s2[i])
            return 1;
        i++;
    }
    if (s1[i] < s2[i])
        return -1;
    else if (s1[i] > s2[i])
        return 1;
    else
        return 0;
}

int main(){
#ifdef DEBUG
    printf("%d\n", strcmp_hook("a", "a"));
    printf("%d\n", strcmp_hook("a", "b"));
    printf("%d\n", strcmp_hook("b", "a"));
    printf("%d\n", strcmp_hook("ab", "a"));
#endif
    return 0;
}
