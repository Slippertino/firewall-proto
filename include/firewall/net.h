#pragma once

#include <stdint.h>

typedef uint32_t ipv4_t;
typedef uint8_t mask_t;

typedef struct {
    ipv4_t ip;
    mask_t mask;
} net_t;

#define MAX_NET_MASK 32
#define ANY_NET "", 0

extern const net_t kAnyNet;

const char* get_ip_by_number(ipv4_t ip, char *buffer);

int net_create_v4(ipv4_t ip, mask_t mask, net_t *res);
int net_create_v4_from_raw(const char *ip_str, mask_t mask, net_t *res);

int net_match(const net_t *target, const net_t *source);
int net_equal(const net_t *n1, const net_t *n2);

void net_serialize(const net_t *net, char *buffer);