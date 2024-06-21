#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <test.h>
#include <firewall/rule.h>
#include <firewall/checker.h>
#include <firewall/rules_storage.h>

static const rule_entry_t storage[] = {
    {
        { "10.0.1.11", MAX_NET_MASK, ANY_PORT }, 
        { "1.1.1.1", MAX_NET_MASK, ANY_PORT },
        IPPROTO_TCP,
        ACCEPT
    },
    {
        { "10.0.2.12", MAX_NET_MASK, ANY_PORT },
        { "1.1.1.1", MAX_NET_MASK, ANY_PORT },
        IPPROTO_TCP,
        DROP
    },
    {
        { "10.0.2.12", MAX_NET_MASK, ANY_PORT },
        { "8.8.8.8", MAX_NET_MASK, ANY_PORT },
        IPPROTO_TCP,
        ACCEPT
    },
    {
        { "10.0.2.12", MAX_NET_MASK, ANY_PORT },
        { "8.8.8.8", MAX_NET_MASK, ANY_PORT },
        IPPROTO_TCP,
        DROP
    },
    {
        { "10.0.2.12", MAX_NET_MASK, ANY_PORT },
        { "1.1.1.1", MAX_NET_MASK, ANY_PORT },
        IPPROTO_TCP,
        DROP
    },
    {
        { "10.0.3.13", MAX_NET_MASK, ANY_PORT },
        { "1.2.3.4", MAX_NET_MASK, ANY_PORT },
        IPPROTO_UDP,
        DROP
    },
    {
        { "10.0.3.13", MAX_NET_MASK, ANY_PORT },
        { "1.2.3.5", MAX_NET_MASK, ANY_PORT },
        IPPROTO_UDP,
        ACCEPT
    },
    {
        { "10.0.3.13", MAX_NET_MASK, ANY_PORT },
        { "10.0.9.1", MAX_NET_MASK, ANY_PORT },
        IPPROTO_TCP,
        DROP
    },
    {
        { "10.0.5.0", 24, ANY_PORT },
        { "10.0.9.1", MAX_NET_MASK, ANY_PORT },
        IPPROTO_TCP,
        ACCEPT
    },
    {
        { ANY_NET, 80 },
        { ANY_NET, 80 },
        IPPROTO_TCP,
        DROP
    },
    {
        { ANY_NET, 80 },
        { ANY_NET, ANY_PORT },
        IPPROTO_TCP,
        ACCEPT
    }
};

static ep_entry_t create_entry(const char *ip, mask_t mask, port_t port) {
    ep_entry_t entry;
    strcpy(entry.ip, ip);
    entry.ip[INET_ADDRSTRLEN] = '\0';
    entry.mask = mask;
    entry.port = port;
    return entry;
}

static session_t create_session(const ep_entry_t src, const ep_entry_t dest, int proto) {
    session_t res;
    session_create(&src, &dest, proto, &res);
    return res;
}

static void test_check(session_t session, status_t exp) {
    printf("test_check: ");
    status_t res = check(&session, NULL);
    ASSERT(res, exp)
}

int main(void) {
    rules_load(storage, sizeof(storage) / sizeof(storage[0]));

    test_check(
        create_session(
            create_entry("10.0.1.11", 32, 11111),
            create_entry("1.1.1.1", 32, 13243),
            IPPROTO_TCP
        ),
        ACCEPT
    );

    test_check(
        create_session(
            create_entry("10.0.3.13", 32, 11111),
            create_entry("1.2.3.4", 32, 13243),
            IPPROTO_UDP
        ),
        DROP
    );

    test_check(
        create_session(
            create_entry("11.0.3.13", 32, 11111),
            create_entry("11.2.3.4", 32, 13243),
            IPPROTO_UDP
        ),
        DROP
    );

    test_check(
        create_session(
            create_entry("10.0.2.12", 32, 11111),
            create_entry("8.8.8.8", 32, 13243),
            IPPROTO_TCP
        ),
        DROP
    );

    return EXIT_SUCCESS;
}