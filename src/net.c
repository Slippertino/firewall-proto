#include <sys/param.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <firewall/net.h>

const net_t kAnyNet = { 0, 0 };

const char* get_ip_by_number(ipv4_t ip, char *buffer) {
    return inet_ntop(AF_INET, &ip, buffer, INET_ADDRSTRLEN);
}

int net_create_v4(ipv4_t ip, mask_t mask, net_t *res) {
    net_t net;
    net.ip = ip;
    if (mask <= MAX_NET_MASK) {
        net.mask = mask;
        *res = net;
        return 0;
    }
    return EINVAL; 
}

int net_create_v4_from_raw(const char *ip_str, mask_t mask, net_t *res) {
    int ec = 0;
    struct in_addr addr;
    if (!mask) {
        *res = kAnyNet;
    } else {
        ec = inet_aton(ip_str, &addr);
        if (!ec)
            return EINVAL;
        if (ec > 0)
            ec = net_create_v4(addr.s_addr, mask, res);
    }
    return ec;
}

int net_match(const net_t *target, const net_t *source) {
    if (!target->mask)
        return 1;
    mask_t lsh = MAX_NET_MASK - target->mask;
    return ((target->ip << lsh) == (source->ip << lsh));
}

int net_equal(const net_t *n1, const net_t *n2) {
    return n1->ip == n2->ip && n1->mask == n2->mask;
}

void net_serialize(const net_t *net, char *buffer) {
    char ip_buffer[INET_ADDRSTRLEN], mask_buffer[4] = {'\0'};
    if (!net->mask)
        sprintf(ip_buffer, "%s", "*");
    else
        get_ip_by_number(net->ip, ip_buffer);
    if (net->mask != MAX_NET_MASK && net->mask)
        sprintf(mask_buffer, "/%d", net->mask);
    sprintf(buffer, "%s%s", ip_buffer, mask_buffer);
}