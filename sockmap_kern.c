#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

struct sock_key {
    uint32_t local_ip;
    uint32_t local_port;
    uint32_t remote_ip;
    uint32_t remote_port;
};

struct bpf_map_def SEC("maps") sock_map = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(int),
    .max_entries = 2,
};

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
    struct sock_key key = {
        .local_ip = skb->local_ip4,
        .local_port = skb->local_port,
        .remote_ip = skb->remote_ip4,
        .remote_port = skb->remote_port,
    };

    long r = bpf_sk_redirect_hash(skb, &sock_map, &key, 0);
    // bpf_printk("prog_verdict: len = %u", skb->len);
    
    // bpf_printk("prog_verdict: <%u> - <%u> %d", skb->local_port,
    //            skb->remote_port, r);
    return r;
}

char _license[] SEC("license") = "GPL";