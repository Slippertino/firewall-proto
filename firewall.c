#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <firewall/checker.h>
#include <firewall/utils.h>
#include <firewall/rules_storage_manager.h>

int read_session(session_t *res) {
    ep_entry_t src, dest;
    src.mask = dest.mask = MAX_NET_MASK;
    int proto, ec = 0;
    while(1) {
        ec = scanf("%s %s %d %d %d", src.ip, dest.ip, &src.port, &dest.port, &proto);
        if (ec != EOF)
            break;
        if (ec == EOF && errno != EINTR) 
            return ec;
    } 
    ec = session_create(&src, &dest, proto, res);
    if (ec) {
        errno = ec;
        perror("Error while reading session");
    }
    return ec;
}

int main(int argc, char** argv) {
    rules_storage_init(argc, argv);

    session_t session;
    int st = 0;
    char 
        session_buffer[250], 
        reason_buffer[250], 
        status_buffer[10];
    while(st != EOF) {
        st = read_session(&session);
        if (st) 
            continue;
        rule_t *matched;
        status_t res = check(&session, &matched);
        sprintf(status_buffer, "%s", status_get_name_by_number(res));
        string_toupper(status_buffer);
        if (!matched)
            sprintf(reason_buffer, "%s", "no rule matched");
        else 
            rule_serialize(matched, reason_buffer);
        session_serialize(&session, session_buffer);
        printf(
            "Packet %s is %s by reason : %s\n", 
            session_buffer, 
            status_buffer, 
            reason_buffer
        );
    }

    return EXIT_SUCCESS;
}