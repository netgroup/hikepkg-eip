// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME mcd

/*
 * Hello world
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include <linux/ipv6.h>

#include "hike_vm.h"
#include "parse_helpers.h"
#include "minimal.h"

#define HBH_TYPE_EIP 0x3e
#define EIP_TYPE_CPT 0x2
#define EIP_MCD_SIZE 40
#define MAX_TTS_SHIFT 22
#define MCD_STACK_LEN 13
#define EIP_IE_MAX_NUMBER 64

#define DELTA_KEY 0
#define TTS_KEY 1
#define ID_KEY 2
#define LD_KEY 3

struct tlv
{
        __u8 type;
        __u8 len;
} __attribute__((packed));

struct mcd
{
        __be16 id_ld;
        __u8 tts;
} __attribute__((packed));

static __always_inline int
ipv6_find_tlv(struct xdp_md *ctx, struct hdr_cursor *cur, int *offset,
              int target, int remaining_bytes)
{
        struct tlv *tlv_ptr;
        for (; remaining_bytes > 1; remaining_bytes -= tlv_ptr->len + 2)
        {
                tlv_ptr = (struct tlv *)cur_header_pointer(ctx, cur, *offset,
                                                           sizeof(*tlv_ptr));
                if (unlikely(!tlv_ptr))
                        return -EBADMSG;
                if (tlv_ptr->type == target)
                {
                        return tlv_ptr->type;
                }
                *offset += tlv_ptr->len + 2;
        }
        return -ENOENT;
}

/* returns the total length in bytes of the LTV given in input */
static __always_inline int eip_len(__u32 *ltv)
{
        return ((bpf_ntohl(*ltv)) >> 24) & 0x3f;
        // return ((((*ltv) >> 24) & 63) + 1) * 4;
}

/* returns the type of the LTV given in input as an unsigned int of 32 bits */
static __always_inline __u32 eip_type(__u32 *ltv)
{
        __u32 mask = 0xffffff;
        __u32 code = ((bpf_ntohl(*ltv)) >> 30);
        return ((bpf_ntohl(*ltv)) & mask) >> (8 * (3 - code));
}

static __always_inline int
eip_find_ltv(struct xdp_md *ctx, struct hdr_cursor *cur, int *offset,
              int target, int remaining_bytes)
{
        __u32 *ltv;
        __u32 type;
        for (int j = 0; remaining_bytes >= 4 && j < EIP_IE_MAX_NUMBER;
             remaining_bytes -= eip_len(ltv), j++)
        {
                ltv = (__u32 *)cur_header_pointer(ctx, cur, *offset, 4);
                if (unlikely(!ltv))
                        return -EBADMSG;
                type = eip_type(ltv);
                if (type == target)
                {
                        return type;
                }
                *offset += eip_len(ltv);
        }
        return -ENOENT;
}

/* key 0 is delta time, key 1 is tts template */
bpf_map(eip_mcd_time, HASH, __u8, __u64, 4);

HIKE_PROG(HIKE_PROG_NAME)
{
        struct mcd(*mcd_stack)[MCD_STACK_LEN];
        struct ipv6_opt_hdr *hbh;
        struct hdr_cursor *cur;
        struct pkt_info *info;
        struct tlv *tlv_ptr;
        __u8 key_delta = DELTA_KEY;
        __u8 key_tts = TTS_KEY;
        __u8 key_id = ID_KEY;
        __u8 key_ld = LD_KEY;
        int remaining_bytes;
        int hvm_ret = 0;
        __u64 *template;
        int offset = 0;
        __u64 boottime;
        __u64 realtime;
        __u64 *delta;
        __u64 *load;
        __u16 id_ld;
        __u32 *ltv;
        __u64 *id;
        __u8 tts;
        int ret;

        /* retrieve packet information from HIKe shared memory*/
        info = hike_pcpu_shmem();
        if (unlikely(!info))
                goto drop;
        /* take the reference to the cursor object which has been saved into
         * the HIKe shared memory
         */
        cur = pkt_info_cur(info);
        /* no need for checking cur != NULL here */

        ret = ipv6_find_hdr(ctx, cur, &offset, NEXTHDR_HOP, NULL, NULL);
        if (unlikely(ret < 0))
        {
                hike_pr_debug("HBH header not found; rc: %d", ret);
                hvm_ret = 1;
                goto out;
        }

        hbh = (struct ipv6_opt_hdr *)cur_header_pointer(
            ctx, cur, offset, sizeof(*hbh));
        if (unlikely(!hbh))
                goto drop;
        /* RFC 2460
         * Length of the Hop-by-Hop Options header is expressed in 8-octet units,
         * not including the first 8 octets.
         * After calculating the number of Bytes, remove 2 relative to HBH header.
         */
        remaining_bytes = (hbh->hdrlen + 1) * 8 - 2;
        offset += 2;
        /* find EIP option */
        ret = ipv6_find_tlv(ctx, cur, &offset, HBH_TYPE_EIP, remaining_bytes);
        if (unlikely(ret < 0))
        {
                hike_pr_debug("EIP option not found; rc: %d", ret);
                hvm_ret = 1;
                goto out;
        }
        tlv_ptr = (struct tlv *)cur_header_pointer(ctx, cur, offset,
                                                   sizeof(*tlv_ptr));
        if (unlikely(!tlv_ptr))
                goto drop;
        /* EIP */
        hike_pr_debug("HBH type: 0x%x", tlv_ptr->type);
        hike_pr_debug("TLV len: %u", tlv_ptr->len);
        /* find PT TLV with MCD stack */
        remaining_bytes = tlv_ptr->len - 2;
        offset += 2;
        ret = eip_find_ltv(ctx, cur, &offset, EIP_TYPE_CPT, remaining_bytes);
        if (unlikely(ret < 0))
        {
                hike_pr_debug("PTC LTV not found; rc: %d", ret);
                hvm_ret = 1;
                goto out;
        }
        ltv = (__u32 *)cur_header_pointer(ctx, cur, offset, 4);
        if (unlikely(!ltv))
                goto drop;
        /* MCD stack */
        hike_pr_debug("EIP type: 0x%x", eip_type(ltv));
        hike_pr_debug("LTV len: %u", eip_len(ltv));
        offset += 4;
        mcd_stack = (struct mcd(*)[MCD_STACK_LEN])cur_header_pointer(
            ctx, cur, offset, sizeof(*mcd_stack));
        if (unlikely(!mcd_stack))
                goto drop;
        hike_pr_debug("mcd0 id_ld: %u, tts: %u", (*mcd_stack)[0].id_ld,
                      (*mcd_stack)[0].tts);
        /* shift right */
        for (int i = 0; i < MCD_STACK_LEN - 1; ++i)
        {
                (*mcd_stack)[MCD_STACK_LEN - 1 - i] = (*mcd_stack)[MCD_STACK_LEN - 2 - i];
        }
        /* read boot time from kernel, read delta between kernel boot time
         * and user space clock real time from map. Add them up and get
         * current clock real time.
         *
         * Need to have started already python script stamp_maps.py to populate
         * map with delta value, if map is empty, the packet is dropped.
         */
        boottime = bpf_ktime_get_boot_ns();
        delta = bpf_map_lookup_elem(&eip_mcd_time, &key_delta);
        if (unlikely(!delta))
        {
                hike_pr_err("could not read delta from map");
                goto drop;
        }
        realtime = boottime + *delta;
        hike_pr_debug("real time (nanoseconds): 0x%llx", realtime);
        /* get tts template from map and compute tts */
        template = bpf_map_lookup_elem(&eip_mcd_time, &key_tts);
        if (unlikely(!template))
        {
                hike_pr_err("could not read tts template from map");
                goto drop;
        }
        hike_pr_debug("tts template shift (bits): %d", *template);
        if (unlikely(*template > MAX_TTS_SHIFT))
        {
                hike_pr_err("tts template shift too large");
                goto drop;
        }
        tts = (__u8)(realtime >> *template);
        hike_pr_debug("tts : 0x%x", tts);
        /* read interface ID and load and build id_ld variable*/
        id = bpf_map_lookup_elem(&eip_mcd_time, &key_id);
        if (unlikely(!id))
        {
                hike_pr_err("could not read interface ID from map");
                goto drop;
        }
        load = bpf_map_lookup_elem(&eip_mcd_time, &key_ld);
        if (unlikely(!load))
        {
                hike_pr_err("could not read interface load from map");
                goto drop;
        }
        /* first 12 bits represent the ID, last 4 bits represent the load */
        id_ld = (*id & 0xfff) << 4 | (*load & 0xf);
        hike_pr_debug("id_ld: 0x%x", id_ld);
        /* add mcd to first position in stack */
        *mcd_stack[0] = (struct mcd){
            .id_ld = bpf_htons(id_ld),
            .tts = tts};

out:
        HVM_RET = hvm_ret;
        return HIKE_XDP_VM;
drop:
        hike_pr_debug("drop packet");
        return HIKE_XDP_ABORTED;
}
EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
char LICENSE[] SEC("license") = "Dual BSD/GPL";
