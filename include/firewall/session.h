#pragma once

#include <firewall/ep.h>

typedef struct {
    ep_t src;
    ep_t dest;
    int proto;
} session_t;

int session_create(
    const ep_entry_t *src, const ep_entry_t *dest, 
    int proto, session_t *res
);

int session_create_with_protoname(
    const ep_entry_t *src, const ep_entry_t *dest, 
    char *protoname, session_t *res
);

int session_equal(const session_t *ep1, const session_t *ep2);
void session_serialize(const session_t *ss, char *buffer);