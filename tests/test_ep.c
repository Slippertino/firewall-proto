#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <test.h>
#include <firewall/ep.h>

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

static void test_ep_create(ep_entry_t in, ep_t out, int exp) {
    printf("test_ep_create: ");
    ep_t res;
    memset(&res, 0, sizeof(res));
    int ec = ep_create(&in, &res);
    ASSERT(ec, exp)
    ASSERT(ep_equal(&res, &out), 1)
}

int main(void) {
    test_ep_create(create_entry("10.0.1.2", 32, 80), create_ep(0x0201000a, 32, 80), 0);
    test_ep_create(create_entry("10.0.1.2", 32, -1), create_ep(0x0201000a, 32, -1), 0);
    test_ep_create(create_entry("10.0.1.2", 32, -222), create_ep(0, 0, 0), EINVAL);
    test_ep_create(create_entry("10.0.1.2", 32, UINT16_MAX + 1), create_ep(0, 0, 0), EINVAL);
    test_ep_create(create_entry("10.0.1.2333", 32, 80), create_ep(0, 0, 0), EINVAL);
    
    return EXIT_SUCCESS;
}