#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <firewall/rules_storage.h>
#include <firewall/static_rules_storage.h>
#include <firewall/utils.h>

static rules_storage_t storage = NULL;

static void storage_reset() {
    storage->size = 0;
    storage->head = NULL;
    storage->tail = NULL;
}

static void storage_init() {
    if (storage) return;
    storage = (rules_storage_t)malloc(sizeof(struct storage_t));
    storage_reset();
}

static void create_tail_node(const rule_t *rule) {
    storage_node_ptr node = (storage_node_ptr)malloc(sizeof(struct storage_node_t));
    node->rule = *rule;
    node->next = NULL;
    if (storage->tail) {
        storage->tail->next = node;
        storage->tail = node;
    } else {
        storage->head = storage->tail = node;
    }
    ++storage->size;
}

static void handle_rule(const rule_t *rule, int ec) {
    char rule_buffer[256];
    if (ec) {
        errno = ec;
#ifndef DISABLE_LOGGING
        perror("Error while loading rule");
#endif
        return;
    }
    rule_serialize(rule, rule_buffer);
    create_tail_node(rule);
#ifndef DISABLE_LOGGING
    printf("Loaded new rule : %s\n", rule_buffer);    
#endif
}

const rules_storage_t rules_get() {
    return storage;
}

void rules_load(const rule_entry_t *entries, int size) {
    storage_init();
    rule_t rule;
    for(int i = 0; i < size; ++i) 
        handle_rule(&rule, rule_create(&entries[i], &rule));
}

void rules_load_static() {
    rules_load(static_storage_get(), static_storage_len());
}

int rules_load_from_file(const char *filename) {
    storage_init();
    FILE *file = fopen(filename, "r");
    if (!file) {
#ifndef DISABLE_LOGGING
        perror("Error while opening the file with rules");
#endif
        return 1;
    }
    ep_entry_t src, dest;
    char proto_buffer[24], status_buffer[24];
    rule_t rule;
    while(fscanf(
        file, "%s %hhu %d %s %hhu %d %s %s", 
        src.ip, &src.mask, &src.port, 
        dest.ip, &dest.mask, &dest.port, 
        proto_buffer, status_buffer
    ) != EOF) {
        string_tolower(proto_buffer);
        string_tolower(status_buffer);
        handle_rule(&rule, rule_create_extended(&src, &dest, proto_buffer, status_buffer, &rule));
    }
    return 0;
}

void rules_set(storage_node_ptr rules) {
    storage_node_ptr cur;
    storage->head = cur = rules;
    if (!cur)
        return;
    storage->size = 1;
    while(cur->next) {
        ++storage->size;
        cur = cur->next;
    }
    storage->tail = cur;
}

storage_node_ptr rules_reset() {
    storage_node_ptr head = storage->head;
    storage->size = 0;
    storage->head = NULL;
    storage->tail = NULL;
    return head;
}

void rules_clear(storage_node_ptr list) {
    storage_node_ptr cur = list;
    while(cur) {
        storage_node_ptr next = cur->next;
        free(cur);
        cur = next;
    }
}