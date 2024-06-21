#include <stddef.h>
#include <firewall/checker.h>
#include <firewall/rules_storage_manager.h>

status_t check(session_t *target, rule_t **matched_rule) {
    const rules_storage_t storage = rules_storage_get();
    storage_node_ptr cur = storage->head;
    status_t status = UNKNOWN_STATUS;
    while(cur) {
        rule_t *rule = &cur->rule;
        if (rule_apply(rule, target)) {
            status = cur->rule.status;
            if (matched_rule)
                *matched_rule = rule;
            if (status == DROP)
                break;
        }
        cur = cur->next;
    }
    if (status == UNKNOWN_STATUS) {
        status = DROP;
        if (matched_rule)
            *matched_rule = NULL;
    }
    return status;
}