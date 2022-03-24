// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    mcd

/*
 * Hello world
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include <linux/ipv6.h>

#include "hike_vm.h"
#include "parse_helpers.h"
#include "minimal.h"

#define HBH_TYPE_EIP 0x3e
#define EIP_TYPE_PT 0x22
#define EIP_MCD_SIZE 40

struct tlv {
    __u8 type;
    __u8 len;
};

struct mcd {
    __u16 id_ld;
    __u8 tts;
} __attribute__((packed));

struct mcd_stack {
    struct mcd mcd1;
    struct mcd mcd2;
    struct mcd mcd3;
    struct mcd mcd4;
    struct mcd mcd5;
    struct mcd mcd6;
    struct mcd mcd7;
    struct mcd mcd8;
    struct mcd mcd9;
    struct mcd mcd10;
    struct mcd mcd11;
    struct mcd mcd12;
} __attribute__((packed));


HIKE_PROG(HIKE_PROG_NAME)
{
    int hbh_remaining_bytes;
    struct ipv6_opt_hdr *hbh;
    struct hdr_cursor *cur;
    struct pkt_info *info;
    struct tlv *tlv_ptr;
    int hvm_ret = 0;
    int offset = 0;
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
    if (unlikely(ret < 0)) {
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
    hbh_remaining_bytes = (hbh->hdrlen + 1) * 8 - 2;
    offset += 2;
    /* find EIP option */
    while (true) {
        tlv_ptr = (struct tlv *)cur_header_pointer(ctx, cur, offset,
                                                   sizeof(*tlv_ptr));
        if (unlikely(!tlv_ptr))
            goto drop;
        if (tlv_ptr->type == HBH_TYPE_EIP) {
            offset += 2;
            hbh_remaining_bytes -= 2;
            break;
        }
        offset += tlv_ptr->len + 2;
        hbh_remaining_bytes -= tlv_ptr->len + 2;
        if (hbh_remaining_bytes < 2) {
            hike_pr_debug("EIP option not found");
            hvm_ret = 1;
            goto out;
        }
    }
    /* EIP */
    tlv_ptr = (struct tlv *)cur_header_pointer(ctx, cur, offset,
                                               sizeof(*tlv_ptr));
    if (unlikely(!tlv_ptr))
        goto drop;
    hike_pr_debug("EIP type: 0x%x", tlv_ptr->type);
    hike_pr_debug("EIP len: %u", tlv_ptr->len);
    /* find PT TLV with MCD stack */
    eip_remaining_bytes = tlv_ptr->len - 2;
    offset += 2;
    while (true) {
        tlv_ptr = (struct tlv *)cur_header_pointer(ctx, cur, offset,
                                                   sizeof(*tlv_ptr));
        if (unlikely(!tlv_ptr))
            goto drop;
        if (tlv_ptr->type == EIP_TYPE_PT) {
            offset += 2;
            eip_remaining_bytes -= 2;
            break;
        }
        offset += tlv_ptr->len + 2;
        eip_remaining_bytes -= tlv_ptr->len + 2;
        if (eip_remaining_bytes < 2) {
            hike_pr_debug("PT-MCD TLV not found");
            hvm_ret = 1;
            goto out;
        }
    }
    

out:
    HVM_RET = hvm_ret;
    return HIKE_XDP_VM;
drop:
    hike_pr_debug("drop packet");
    return HIKE_XDP_ABORTED;
}
EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
char LICENSE[] SEC("license") = "Dual BSD/GPL";
