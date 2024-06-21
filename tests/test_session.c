#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <test.h>
#include <firewall/session.h>

static ep_entry_t create_entry(const char *ip, mask_t mask, port_t port) {
    ep_entry_t entry;
    strcpy(entry.ip, ip);
    entry.ip[INET_ADDRSTRLEN] = '\0';
    entry.mask = mask;
    entry.port = port;
    return entry;
}

static ep_t create_ep(ipv4_t ip, mask_t mask, port_t port) {
    ep_t ep = { { ip, mask }, htonl(port) };
    return ep;
}

static session_t create_session(ep_t src, ep_t dest, int proto) {
    session_t res = { src, dest, proto };
    return res;
}

static void test_session_create(ep_entry_t src, ep_entry_t dest, int proto, session_t exp, int out) {
    printf("test_session_create: ");
    session_t res;
    memset(&res, 0, sizeof(res));
    int ec = session_create(&src, &dest, proto, &res);
    ASSERT(ec, out)
    ASSERT(session_equal(&res, &exp), 1)
}

int main(void) {
    test_session_create(
        create_entry("0.0.0.0", 32, 80),
        create_entry("0.0.0.0", 32, 80),
        IPPROTO_TCP,
        create_session(
            create_ep(0, 32, 80),
            create_ep(0, 32, 80),
            IPPROTO_TCP
        ),
        0
    );

    test_session_create(
        create_entry("0.0.0.0", 32, 80),
        create_entry("0.0.0.0", 32, 80),
        -1,
        create_session(
            create_ep(0, 0, 0),
            create_ep(0, 0, 0),
            0
        ),
        EINVAL
    );
    
    test_session_create(
        create_entry("0.0.0.0", 32, 80),
        create_entry("0.0.0.0", 32, -100),
        -1,
        create_session(
            create_ep(0, 0, 0),
            create_ep(0, 0, 0),
            0
        ),
        EINVAL
    );

    return EXIT_SUCCESS;
}