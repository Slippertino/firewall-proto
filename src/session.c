#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <firewall/session.h>

int session_create(const ep_entry_t *src, const ep_entry_t *dest, int proto, session_t *res) {
    int ec = 0;
    if (!getprotobynumber(proto))
        return EINVAL;
    res->proto = proto;
    if (!ec)
        ec = ep_create(src, &res->src);
    if (!ec)
        ec = ep_create(dest, &res->dest);
    return ec;
}

int session_create_with_protoname(const ep_entry_t *src, const ep_entry_t *dest, char *protoname, session_t *res) {
    struct protoent *proto = getprotobyname(protoname);
    if (!proto)
        return EINVAL;
    return session_create(src, dest, proto->p_proto, res);
}

int session_equal(const session_t *s1, const session_t *s2) {
    return 
        s1->proto == s2->proto &&
        ep_equal(&s1->src, &s2->src) && 
        ep_equal(&s1->dest, &s2->dest);
}

void session_serialize(const session_t *ss, char *buffer) {
    char src_buffer[64], dest_buffer[64], proto_buffer[40];
    ep_serialize(&ss->src, src_buffer);
    ep_serialize(&ss->dest, dest_buffer);
    sprintf(proto_buffer, "%s", getprotobynumber(ss->proto)->p_name);
    sprintf(buffer, "%s --> %s --> %s", src_buffer, proto_buffer, dest_buffer);
}