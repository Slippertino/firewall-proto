#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <firewall/rule.h>

typedef struct {
    status_t number;
    const char *name;
} status_desc_t;

static status_desc_t statuses[] = {
    { DROP, "drop" },
    { ACCEPT, "accept" }
};

const char* status_get_name_by_number(status_t status) {
    return statuses[status].name;
}

status_t status_get_number_by_name(const char *name) {
    for(int i = 0; i < UNKNOWN_STATUS; ++i) {
        status_desc_t *cur = &statuses[i];
        if (!strcmp(name, cur->name))
            return cur->number;
    }
    return UNKNOWN_STATUS;
}

static int check_endpoints(const ep_t *target, const ep_t *source) {
    if (target->port != ANY_PORT && 
        target->port != source->port)
        return 0;
    return net_match(&target->host, &source->host);
}

int rule_create(const rule_entry_t *entry, rule_t *res) {
    if (entry->status == UNKNOWN_STATUS)
        return EINVAL;
    res->status = entry->status;
    return session_create(&entry->src, &entry->dest, entry->proto, &res->session);
}

int rule_create_extended(const ep_entry_t *src, const ep_entry_t *dest, char *protoname, char *statusname, rule_t *res) {
    status_t status = status_get_number_by_name(statusname);
    if (status == UNKNOWN_STATUS)
        return EINVAL;
    res->status = status;
    return session_create_with_protoname(src, dest, protoname, &res->session);
}

int rule_apply(const rule_t *rule, const session_t *session) {
    return 
        rule->session.proto == session->proto &&
        check_endpoints(&rule->session.src, &session->src) &&
        check_endpoints(&rule->session.dest, &session->dest);
}

int rule_equal(const rule_t *r1, const rule_t *r2) {
    return 
        r1->status == r2->status &&
        session_equal(&r1->session, &r2->session);
}

void rule_serialize(const rule_t *rule, char *buffer) {
    char session_buffer[200], status_buffer[20];
    session_serialize(&rule->session, session_buffer);
    sprintf(status_buffer, "%s", status_get_name_by_number(rule->status));
    sprintf(buffer, "{ %s, status: %s }", session_buffer, status_buffer);
}