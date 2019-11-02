# About

A simple BDD-based naive dataplane verifier. Incremental verification supported. Attached a [microbenchmark](#Microbenchmarks) vs AP verifier.

# Dependencies

- Python 3.7
  - pyyaml 5.1.2
  - pyeda 0.28.0

# Usage

1. Install dependencies

   Make sure python version is 3.7

   Use ./Pipfile for pipenv

   or

   `pip3 install pyyaml`

   `pip3 install pyeda`

2. Run sample trace

   `python3 main.py`

# Key Components

- `bddutils.py`
  - `acl2pred`  Implements Algorithm 1 in [1]. Converts an ACL to a predicate, represented by BDD
  - `ft2preds` Implements Algorithm 2 in [1]. Converts a forwarding table to forwarding predicates, each represented by BDD
- `reachability.py`
  - `judge_query` Computes reachability tree from input port to output port via Deep First Search, see whether the invariant holds or not
- `main.py` Data structures and implementatin of Atomic Predicates algorithm 
- `./traces`



# Microbenchmarks

- Execution time breakdown for sample trace run

| Time (ms)       |                               | BDD Verifier                                                 | AP Verifier                                                  | Bound                                                        |
| --------------- | ----------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Pre-computation | Build BDD Predicate           | 2 ACLs {48, 152}<br />4 FTs {55, 29, 28, 41}<br />Total = 353 ms | 2 ACLs {48, 154}<br />4 FTs {57, 30, 31, 49}<br />Total = 369 ms | O(n)<br />O(e)                                               |
|                 | Compute Atomic Predicates     | N/A                                                          | AP_ACL = 374 ms<br />AP_FT = 29 ms                           | O(# of APs)<br />By authors, usually efficient for small and very-large networks |
|                 | Decompose Predicates with APs | N/A                                                          | 2 ACLs {1222, 253}<br />11 FPs {3, 8, 0, 3, 6, 3, 6, 4, 3, 3, 0}<br />Total = 1508 ms | O(n\*(# of APs))<br />O(e\*(# of APs))<br />*Easily eliminate by interleaving with computing APs* |
| Query           | Judge queries                 | 7 Queries {135, 130, 82, 88, 103, 111, 87}<br />Total = 736 ms | 7 Queries {302, 397, 160, 134, 135, 140, 109}<br />Total = 1377 ms | See breakdown below, AP verifier is slower for now but potentially scales better |
| Total           | Sample trace                  | 1089 ms                                                      | 3657 ms                                                      |                                                              |

- Discuss:
  - In total, for small scale network like sample trace, AP verifier is slower than naive BDD verifier in both pre-computation time and query judgement time.
  - For pre-computation, both methods need to build BDD predicates, in exactly the same way and same time.
  - For pre-computation, AP verifier, however, needs to compute atomic predicates. This is a significant computation cost for AP verifier. Decomposing original predicates with APs could be eliminated with improved algorithm.
  - Forwarding predicates (less than 32 bit) are much simpler than ACL predicates (up to 104 bit)
  - For a single query, AP verifier is now still slower than BDD verifier, we should look into that (see below)

- Execution time breakdown for judging 1st query (119 ms VS 300 ms, correspondes to 135 ms VS 302 ms in table above with multiple-run fluctuations) in sample trace

| Time (ms)                          | BDD Verifier               | AP Verifier                       | Bound       |
| ---------------------------------- | -------------------------- | --------------------------------- | ----------- |
| Build query predicate              | 59 ms                      | 53 ms                             | O(1)        |
| Decompose query predicate with APS | N/A                        | AP_ACL = 197 ms<br />AP_FT = 4 ms | O(# of APs) |
| DFS                                | with BDD operation = 56 ms | with set operation = 0.04 ms      | O(n^2)      |
| Other                              | 6 ms                       | 46 ms                             | O(1)        |
| Total                              | 119 ms                     | 300 ms                            |             |

- Discuss
  - Here we do not pre-compute reachability trees, instead, each query needs a DFS-based search. We consider time cost for computing reachability trees to be similiar to this
  - Both methods need to build query predicate (up to 104 BDD variables), which takes a significant portion of time. This is O(1) and hopefully could be optimized with better implementation
  - AP verifier needs to decompose query with APs, and ACL APs are complex (with up to 104 BDD variables), this is a downside of AP verifier
  - Despite so many downsides, AP verifier boosts DFS by 3 orders of magnitude, even with a naive set implementation. With DFS taking the most significant bound O(n^2), AP verifier might be able to scale better then BDD verifier and other SMT-based methods