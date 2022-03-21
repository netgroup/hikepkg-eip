// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* HIKe Prog Name comes always first */
#define HIKE_PROG_NAME    hello

/*
 * Hello world
 */

#define HIKE_PRINT_LEVEL HIKE_PRINT_LEVEL_DEBUG

#include "hike_vm.h"
#include "parse_helpers.h"
#include "minimal.h"

HIKE_PROG(HIKE_PROG_NAME)
{
    hike_pr_debug("Hello World");
    return HIKE_XDP_VM;
}
EXPORT_HIKE_PROG_1(HIKE_PROG_NAME);
char LICENSE[] SEC("license") = "Dual BSD/GPL";
