// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#include <lib/policy.h>
#include "lib/policy.h"

#define REMOTE_IDENTITY		112233
#define SHARED_HANDLE       42

static __always_inline int
check_egress_policy(struct __ctx_buff *ctx, __u32 dst_id, __u8 proto, __be16 dport)
{
	__u8 match_type;
	__u8 audited;
	__s8 ext_err;
	__u16 proxy_port;
	__u32 cookie;

	return policy_can_egress(ctx, 0 /* ignored */, dst_id,
				 0 /* ICMP only */,
				 dport, proto, 0 /* ICMP only */,
				 &match_type, &audited, &ext_err, &proxy_port,
				 &cookie);
}

CHECK("tc", "shared_policy_lookup")
int shared_policy_lookup_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("Shared Policy fallback", {
		int ret;

		/* No policy in legacy map, add to shared map */
		policy_add_shared_entry(SHARED_HANDLE, REMOTE_IDENTITY, 0 /* CT_EGRESS */, IPPROTO_UDP,
					      __bpf_htons(80), false);
        
        /* Link endpoint to shared handle */
        /* Use endpoint ID 0 as EFFECTIVE_EP_ID is 0 in test env usually? 
           Actually policy_can_egress uses helper to get ID? 
           In tests, context might not have ID? 
           policy.h uses separate arg or context? 
           policy_can_egress callers usually pass src_id/dst_id.
           Ah, `policy_can_egress` takes `ctx` and extracts.
           
           Wait, `policy_lookup_shared` uses `local_id`.
           In `policy_can_egress`, `local_id` comes from `ctx` or args?
           It calculates it? 
           Actually `policy.h`:
             __u32 id = __policy_can_access(...);
           __policy_can_access uses `policy_lookup_shared(local_id, ...)`
           
           In `policy_can_egress`:
             return __policy_can_access(ctx, local_id, ...);
             
           Where does `local_id` come from?
             It is NOT passed to `__policy_can_access`.
             `__policy_can_access` calls `policy_lookup_shared`.
             Arguments to `__policy_can_access`: (ctx, local_id, remote_id, ...)
           
           In `policy_can_egress`:
             return __policy_can_access(ctx, 0, dst_id, ...);
             Passed local_id is 0 ??
           
           Let's check `policy.h` `policy_can_egress` implementation again.
        */
        
        /* Assuming local_id is 0 for the test context if not set */
        policy_update_overlay(0, SHARED_HANDLE);

		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(80));
		assert(ret == CTX_ACT_OK);
		
		/* Verify blocking works too */
		ret = check_egress_policy(ctx, REMOTE_IDENTITY, IPPROTO_UDP,
					  __bpf_htons(81));
		assert(ret == DROP_POLICY);
	});

	test_finish();
}
