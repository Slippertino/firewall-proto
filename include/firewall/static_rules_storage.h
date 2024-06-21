#pragma once

#include <stdint.h>
#include <firewall/rule.h>

const rule_entry_t* static_storage_get();
int static_storage_len();