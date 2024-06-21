#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <test.h>
#include <firewall/rule.h>

static ep_entry_t create_entry(const char *ip, mask_t mask, port_t port) {
    ep_entry_t entry;
    strcpy(entry.ip, ip);
    entry.ip[INET_ADDRSTRLEN] = '\0';
    entry.mask = mask;
    entry.port = port;
    return entry;
}

static ep_t create_ep(ipv4_t ip, mask_t mask, port_t port) {
    ep_t ep = { { ip, mask }, port };
    return ep;
}

static session_t create_session(ep_t src, ep_t dest, int proto) {
    session_t res = { src, dest, proto };
    return res;
}

static void test_rule_apply(
    ep_entry_t src, ep_entry_t dest, int proto,
    session_t session, 
    int exp
) {
    printf("test_rule_apply: ");
    rule_entry_t entry = { src, dest, proto, DROP };
    rule_t rule;
    rule_create(&entry, &rule);
    int out = rule_apply(&rule, &session);
    ASSERT(out, exp)
}

int main(void) {
    test_rule_apply(
        create_entry("0.0.0.0", 32, 80),
        create_entry("0.0.0.0", 32, 80),
        IPPROTO_TCP,
        create_session(
            create_ep(0, 32, 80),
            create_ep(0, 32, 80),
            IPPROTO_TCP
        ),
        1
    );

    test_rule_apply(
        create_entry(ANY_NET, 80),
        create_entry(ANY_NET, 441),
        IPPROTO_TCP,
        create_session(
            create_ep(0, 32, 80),
            create_ep(0, 32, 444),
            IPPROTO_TCP
        ),
        0
    );

    test_rule_apply(
        create_entry("10.0.1.2", 24, 80),
        create_entry("0.0.0.0", 32, 441),
        IPPROTO_UDP,
        create_session(
            create_ep(0x1101000a, 32, 80),
            create_ep(0, 32, 441),
            IPPROTO_UDP
        ),
        1
    );

    test_rule_apply(
        create_entry("10.0.1.2", 24, 80),
        create_entry("0.0.0.0", 32, 441),
        IPPROTO_UDP,
        create_session(
            create_ep(0x1102000a, 32, 80),
            create_ep(0, 32, 441),
            IPPROTO_UDP
        ),
        0
    );

    test_rule_apply(
        create_entry(ANY_NET, ANY_PORT),
        create_entry(ANY_NET, ANY_PORT),
        IPPROTO_UDP,
        create_session(
            create_ep(0xfffffff, 32, 833),
            create_ep(0xaaaaaaa, 32, 4431),
            IPPROTO_UDP
        ),
        1
    );

    return EXIT_SUCCESS;
}