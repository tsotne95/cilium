# Speaker Script: Shared Policy Map Presentation

## Slide 1: Title Slide
"Good afternoon everyone. Today I'm going to walk you through the feature we've been working on: the Layered Shared Policy Map. I'll explain why it's a critical stability fix, share our validation results from the 'Yahoo' scenario reproduction, and outline the path to massive memory savings in Phase 2."

## Slide 2: The Challenge: BPF Map Exhaustion "The Cliff"
"First, let's understand the problem. Cilium uses BPF maps attached to every pod to store security rules. These maps have a hard physical limit—usually 16,000 entries. 
For 99% of users, this is fine. But for our 'Heavy Policy' customers, it's a disaster. If they need 20,000 rules, the map fills up, hits the limit, and the pod literally creates a 'PolicyEntryMaxExceeded' error. 
It's a cliff. The moment you cross that line, your service goes down. There's no degradation; it's just an outage."

## Slide 3: Customer Impact: The "Yahoo" Scenario
"This isn't theoretical. We saw this with high-profile customers like Yahoo. They had a requirement to allow-list thousands of partner IPs. 
Because of the map limit, they couldn't launch their pods. They were stuck between a rock and a hard place: either weaken their security posture by deleting rules, or accept that they couldn't scale their application. That's a blocker we had to fix."

## Slide 4: The Solution: Layered Shared Policy Map
"So, how did we fix it? We moved from a single bucket to a two-tier system. 
Think of Tier 1 (the 'Overlay') as a small cache in the pod. It holds unique rules and pointers.
Tier 2 (the 'Shared Map') is a massive, shared storage pool for the entire node.
Instead of trying to stuff 20,000 rules into the small local bucket, we put them in the big shared pool and just put a single 'reference pointer' in the local bucket.
This effectively removes the per-pod limit."

## Slide 4: How It Works: Intelligent Offloading
"A common question is: 'What happens if the shared map is full?' or 'What about security denies?'
We built an intelligent sorting engine to handle this:
1.  **Safety First:** Deny rules always stay local. We never risk sharing them.
2.  **Fill the Pool:** We take the big Allow rules and fill up the Shared Map slots (default 16 slots).
3.  **Graceful Spillover:** If a policy is truly massive and fills all shared slots, the extra rules simply 'spill over' back to the local map.
This means the system is unbreakable. Best case? 99% savings. Worst case? It behaves exactly like the legacy system. There is no downside risk."

## Slide 5: Architecture: Legacy vs. Shared Mode
"Here's a visual comparison. 
**Legacy Mode:** Every pod tries to hold its own copy of all 17,000 rules. Pod A crashes. Pod B crashes.
**Shared Mode:** We store the 17,000 rules ONCE (conceptually) in the Shared Map. Pod A just holds a pointer saying 'I use that block of rules.' Pod B does the same.
The result? The pods stay light, and the system stays stable."

## Slide 5: Deep Dive Example: The "20k Rules" Problem
"Let's zoom in on a specific example to make this concrete.
Imagine Pod A needs to reach 20,000 partner IPs.
**In Legacy Mode**, we try to shove all 20,000 IP rules into the Pod's local map. It hits entry 16,385, the kernel says 'No Space', and the update fails. The pod crashes.
**In Shared Mode**, we change the game. The Pod's local map doesn't store the IPs anymore. It just stores a single 'Pointer'—think of it as a bookmark—that says 'I use Shared Block #100'.
The actual 20,000 IPs live in the Shared Map, which we can size as large as we need. Result: The pod map is empty, the shared map holds the data, and everything works."

## Slide 6: Validation: Benchmark (The Yahoo Repro)
"We didn't just code this; we reproduced the customer's pain. We built a benchmark simulating 20 pods each getting hit with a heavy set of CIDR rules—exactly what breaks the legacy system. 
We wanted to prove that under these specific crushing conditions, the new architecture holds up."

## Slide 7: Success Results: Map Exhaustion Solved
"The results were binary and clear.
In **Legacy Mode**, the local maps filled up instantly. We saw the familiar warning signs.
In **Shared Mode**, look at the numbers: The local map only held about 50 entries—these are just the pointers and metadata. The heavy lifting (1,072 entries) happened in the Shared Map.
Most importantly: **100% Stability.** The pods accepted the policy and kept running. The crash is solved."


## Slide 8: Phase 2: The Future - Global Deduplication
"Now, let's talk about the 'End State.' This is where we change the fundamental economics of the cluster.
Phase 1 solves the **Reliability** (the crash). Phase 2 solves the **Scalability** (the cost).

**The Math:**
Think of the 'Yahoo' case. 100 pods, each with 20,000 rules.
Today (Legacy), we pay for that data 100 times. That's **2 Million entries**.
In Phase 2, we pay for it **ONCE**. That's just **20,000 entries**.
We go from Multiplicative Cost ($O(N)$) to Constant Cost ($O(1)$).

**Which Policies Benefit?**
As the table shows, this isn't random.
*   **Big Wins:** External Allow Lists ('Allow Partner X'). These are heavy and identical across thousands of pods. We get **1000x** savings here.
*   **Small Wins:** Micro-segmentation. If a rule is unique to one pod, we don't save much.
*   **No Change:** Local Redirects. We keep these private for safety.

**The Bottom Line:** For our biggest, heaviest customers, this update reduces their memory footprint by over 99%."

## Slide 9: Rollout Plan & Next Steps
"So here is our recommendation:
1.  **Release Phase 1 Now.** It fixes the outage. Customers hitting the limit need this today. It is verifying, stable, and safe.
2.  **Fast-Follow with Phase 2.** We will deploy the hashing logic to unlock the memory savings for our large-scale users.

## Slide 10: Configuration & Flexibility: Tailoring to the Customer
"One detail I want to highlight is that we didn't just hardcode this. We added specific flags to make it tunable for different use cases.
For example, we have the `mode` flag to toggle the feature safely.
We also have `quota` controls. This is huge for our multi-tenant customers. If one team writes a bad policy with 1 million rules, we can cap them so they don't eat up the entire shared map and starve other teams.
We can essentially 'tier' our support: Default for most, but 'High Capacity' mode for customers like Yahoo, just by changing two flags."

## Slide 11: Summary for PMs
"In summary: We faced a hard blocker with Map Exhaustion. We solved it by re-architecting to a Shared Map model. It works, it's verified, and it unblocks our key customers. We are ready to ship."

"Questions?"
