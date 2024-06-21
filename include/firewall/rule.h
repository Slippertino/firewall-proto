#pragma once

#include <firewall/session.h>

typedef enum {
    DROP = 0,
    ACCEPT,
    UNKNOWN_STATUS
} status_t;

const char* status_get_name_by_number(status_t status);
status_t status_get_number_by_name(const char *name);

typedef struct {
    session_t session;
    status_t status;
} rule_t;

typedef struct {
    ep_entry_t src;
    ep_entry_t dest;
    int proto;
    status_t status;
} rule_entry_t;

int rule_create(const rule_entry_t *entry, rule_t *res);
int rule_create_extended(const ep_entry_t *src, const ep_entry_t *dest, char *protoname, char *statusname, rule_t *res);

int rule_apply(const rule_t *rule, const session_t *session);
int rule_equal(const rule_t *r1, const rule_t *r2);
void rule_serialize(const rule_t *rule, char *buffer);
