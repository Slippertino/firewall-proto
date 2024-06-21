#include <stdlib.h>
#include <string.h>
#include <test.h>
#include <firewall/utils.h>

static void test_string_tolower(const char* in, const char* out) {
    printf("test_string_tolower: %s --> %s", in, out);
    int size = strlen(in);
    char *buff = (char*)malloc(size + 1);
    strcpy(buff, in);
    buff[size] = '\0';
    string_tolower(buff);
    ASSERT(strcmp(buff, out), 0)
    free(buff);
}

static void test_string_toupper(const char* in, const char* out) {
    printf("test_string_toupper: %s --> %s", in, out);
    int size = strlen(in);
    char *buff = (char*)malloc(size + 1);
    strcpy(buff, in);
    buff[size] = '\0';
    string_toupper(buff);
    ASSERT(strcmp(buff, out), 0)
    free(buff);
}

int main(void) {
    test_string_tolower("", "");
    test_string_tolower("HELLO", "hello");
    test_string_tolower("some_STRING", "some_string");

    test_string_toupper("", "");
    test_string_toupper("hello", "HELLO");
    test_string_toupper("some_STRING", "SOME_STRING");

    return EXIT_SUCCESS;
}
