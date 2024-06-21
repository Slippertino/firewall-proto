#pragma once

#include <limits.h>
#include <netinet/in.h>
#include <firewall/net.h>

typedef uint32_t port_t;

port_t port_from_network(port_t port);

#define ANY_PORT UINT32_MAX

typedef struct {
    net_t host;
    port_t port;
} ep_t;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    mask_t mask;
    port_t port;
} ep_entry_t;

int ep_create(const ep_entry_t *entry, ep_t *res);
int ep_equal(const ep_t *ep1, const ep_t *ep2);
void ep_serialize(const ep_t *ep, char *buffer);
