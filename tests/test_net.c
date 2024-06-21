#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <test.h>
#include <firewall/net.h>

static net_t create_net(ipv4_t ip, mask_t mask) {
    net_t res = { ip, mask };
    return res;
}

static net_t create_net_raw(const char *ip, mask_t mask) {
    net_t res;
    net_create_v4_from_raw(ip, mask, &res);
    return res;
}

static void test_get_ip_by_number(ipv4_t in, const char *out) {
    printf("test_get_ip_by_number: %d <--> %s", in, out);
    char buffer[INET_ADDRSTRLEN];
    ASSERT(strcmp(get_ip_by_number(in, buffer), out), 0);
}

static void test_net_create_v4(ipv4_t ip, mask_t mask, int exp) {
    printf("test_net_create_v4: ");
    net_t res;
    int ec = net_create_v4(ip, mask, &res);
    ASSERT(ec, exp);
}

static void test_net_create_v4_from_raw(const char *ip, mask_t mask, int exp_ec, net_t exp_res){
    printf("test_net_create_v4_from_raw: ");
    net_t res;
    memset(&res, 0, sizeof(res));
    int ec = net_create_v4_from_raw(ip, mask, &res);
    ASSERT(exp_ec, ec)
    ASSERT(net_equal(&res, &exp_res), 1)
}

static void test_net_match(net_t target, net_t source, int exp) {
    printf("test_net_match: ");
    int res = net_match(&target, &source);
    ASSERT(res, exp)
}

int main(void) {
    test_get_ip_by_number(0x0, "0.0.0.0");
    test_get_ip_by_number(0x0201000a, "10.0.1.2");

    test_net_create_v4(0, 31, 0);
    test_net_create_v4(0, 33, EINVAL);
    test_net_create_v4(0, 200, EINVAL);

    test_net_create_v4_from_raw("10.0.1.2", 32, 0, create_net(0x0201000a, 32));
    test_net_create_v4_from_raw("10.0.1.2", 0, 0, kAnyNet);
    test_net_create_v4_from_raw("10.0.1.2", 200, EINVAL, create_net(0, 0));
    test_net_create_v4_from_raw("abc", 32, EINVAL, create_net(0, 0));

    test_net_match(create_net_raw("10.0.1.2", 32), create_net_raw("10.0.1.2", 32), 1);
    test_net_match(create_net_raw("10.0.1.2", 24), create_net_raw("10.0.1.255", 32), 1);
    test_net_match(create_net_raw("10.0.1.2", 0), create_net_raw("255.255.255.255", 32), 1);
    test_net_match(create_net_raw("10.0.10.20", 24), create_net_raw("10.0.12.255", 32), 0);

    return EXIT_SUCCESS;
}