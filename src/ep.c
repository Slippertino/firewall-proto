#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <firewall/ep.h>

port_t port_from_network(port_t port) {
    return port <= UINT16_MAX
        ? ntohl(port) >> (CHAR_BIT * sizeof(port) / 2)
        : port;
}

static int validate_port(port_t port) {
    int res = port <= UINT16_MAX || port == ANY_PORT;
    return res ? 0 : EINVAL;
}

int ep_create(const ep_entry_t *entry, ep_t *res) {
    net_t net;
    port_t port = entry->port;
    int ec = net_create_v4_from_raw(entry->ip, entry->mask, &net);
    if (!ec)
        ec = validate_port(port);
    if (!ec) {
        res->host = net;
        res->port = port;
    }
    return ec;
}

int ep_equal(const ep_t *ep1, const ep_t *ep2) {
    return 
        ep1->port == ep2->port &&
        net_equal(&ep1->host, &ep2->host);
}

void ep_serialize(const ep_t *ep, char *buffer) {
    char net_buffer[30], port_buffer[6];
    net_serialize(&ep->host, net_buffer);
    port_t port = ep->port;
    if (port == ANY_PORT)
        sprintf(port_buffer, "%s", "*");
    else
        sprintf(port_buffer, "%u", port);
    sprintf(buffer, "[%s, %s]", net_buffer, port_buffer);
}