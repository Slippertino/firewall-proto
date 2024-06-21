#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <firewall/rules_storage_manager.h>

static int init = 0;
static char *filename = NULL;
static volatile sig_atomic_t upd = 0;

static void rules_storage_rewrite_from_file() {
    printf("Start updating firewall rules...\n");
    storage_node_ptr old = rules_reset();
    if (rules_load_from_file(filename)) {
        fprintf(stderr, "Failed to update firewall rules. Restoring previous...\n");
        rules_set(old);
    } else {
        rules_clear(old);
        printf("Firewall rules were successfully updated.\n");
    }
}

static void update_handler(int) {
    upd = 1;
}

static void register_signal() {
    struct sigaction sig;
    memset(&sig, 0, sizeof(sig));
    sig.sa_handler = update_handler;
    sigset_t  set; 
    sigemptyset(&set);                                                             
    sigaddset(&set, SIGHUP); 
    sig.sa_mask = set;
    sigaction(SIGHUP, &sig, NULL);
}

void rules_storage_init(int argc, char** argv) {
    if (init)
        return;
    init = 1;
    printf("Start loading firewall rules...\n");
    int ec = 0;
    if (argc > 1) {
        filename = argv[1];
        ec = rules_load_from_file(argv[1]);
    } else {
        rules_load_static();
    }
    if (ec) {
        fprintf(stderr, "Failed to load firewall rules.\n");
        exit(EXIT_FAILURE);
    }
    printf("Firewall rules were successfully loaded.\n");
    register_signal();
}

const rules_storage_t rules_storage_get() {
    if (upd && filename) {
        rules_storage_rewrite_from_file();
        upd = 0;
    }
    return rules_get();
}