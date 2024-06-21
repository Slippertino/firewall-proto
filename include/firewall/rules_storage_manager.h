#pragma once

#include <firewall/rules_storage.h>

void rules_storage_init(int argc, char** argv);
const rules_storage_t rules_storage_get();