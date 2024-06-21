#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <firewall/session.h>

int gen(int min, int max) {
    return rand() % (max - min + 1) + min;
}

void generate_net(net_t *net) {
    net->mask = gen(0, MAX_NET_MASK);
    ipv4_t ip = 0;
    for(int i = 0; i < sizeof(net->ip) - 1; ++i) {
        ip += gen(0, UCHAR_MAX);
        ip <<= CHAR_BIT;
    }
    ip += gen(0, UCHAR_MAX);
    net->ip = ip;
}

void generate_ep(ep_t *ep) {
    generate_net(&ep->host);
    ep->port = gen(ANY_PORT, USHRT_MAX);
}

void generate_session(session_t *session) {
    static const int enabled_protos[] = {
        IPPROTO_TCP,
        IPPROTO_UDP
    };
    static const int protos_size = 
        sizeof(enabled_protos) / sizeof(enabled_protos[0]);
    generate_ep(&session->src);
    generate_ep(&session->dest);
    session->proto = enabled_protos[gen(0, protos_size - 1)];
}

const int kGenLimit = 30;

int get_limit(int argc, char **argv) {
    return argc > 1 
        ? atoi(argv[1])
        : kGenLimit;
}

int main(int argc, char **argv) {
    srand(time(NULL));
    int limit = get_limit(argc, argv);
    session_t session;
    char 
        src_ip[INET_ADDRSTRLEN],
        dest_ip[INET_ADDRSTRLEN];
    for(int i = 0; i < limit; ++i) {
        generate_session(&session);
        printf("%s %s %d %d %d\n", 
            get_ip_by_number(session.src.host.ip, src_ip),
            get_ip_by_number(session.dest.host.ip, dest_ip),
            session.src.port, 
            session.dest.port, 
            session.proto
        );
    }
    return EXIT_SUCCESS;
}