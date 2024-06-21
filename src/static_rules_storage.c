#include <netinet/in.h>
#include <firewall/static_rules_storage.h>

static const rule_entry_t static_storage[] = {
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

int static_storage_len() {
    int sz = sizeof(static_storage);
    return sz
        ? sz / sizeof(static_storage[0])
        : sz;
}

const rule_entry_t* static_storage_get() {
    return static_storage;
}