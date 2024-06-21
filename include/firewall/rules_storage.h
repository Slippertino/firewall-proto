#pragma once

#include <firewall/rule.h>

typedef struct storage_node_t {
    rule_t rule;
    struct storage_node_t *next;
} *storage_node_ptr;

typedef struct storage_t {
    int size;
    storage_node_ptr head;
    storage_node_ptr tail;
} *rules_storage_t;

void rules_load(const rule_entry_t *entries, int size);
void rules_load_static();
int rules_load_from_file(const char *filename);

void rules_set(storage_node_ptr rules);
storage_node_ptr rules_reset();
void rules_clear(storage_node_ptr list);

const rules_storage_t rules_get();