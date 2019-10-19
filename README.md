# About

An implementation of dataplane verification based on [Real-time Verification of Network Properties using Atomic Predicates](http://www.cs.utexas.edu/users/lam/Vita/Cpapers/Yang_Lam_AP_Verifier_2013.pdf)

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
- `aputils.py`
  - `preds2atomic_preds` Implements Algorithm 3 in [1]. Computes atomic predicates for a set of predicates, represented by a list of BDDs
  - `decompose_pred` Given a predicate and a atomic predicates set, represent the predicate with indexes of composing atomic predicates
- `reachability.py`
  - `judge_query` Computes reachability tree from input port to output port via Deep First Search, see whether the invariant holds or not
- `main.py` Data structures and implementatin of Atomic Predicates algorithm 
- `./traces`