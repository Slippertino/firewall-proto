#include <ctype.h>
#include <firewall/utils.h>

char* string_tolower(char *s) {
    char *res = s;
    while(*s != '\0')
        *s++ = tolower(*s);
    return res;
}

char* string_toupper(char *s) {
    char *res = s;
    while(*s != '\0')
        *s++ = toupper(*s);
    return res;    
}