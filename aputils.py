from typing import Set, List
from bddutils import *
from pyeda.boolalg.bfarray import farray

# functions for atomic predicates


def pred2atomic_pred(pred: farray) -> Set[farray]:
    """Equation 2

    Input: A single predicate.
    Output: Its atomic predicates.
    """
    if pred.is_one() or pred.is_zero():
        return {bdd_true}
    else:
        return {pred, ~pred}

def preds2atomic_preds(preds: Set[farray]) -> List[farray]:
    """Algorithm 3

    Input: A set of predicates.
    Output: A list of atomic predicates.
    """

    for i, pred in enumerate(preds):
        if i == 0:
            atomic_preds = pred2atomic_pred(pred)
        atomic_preds = {(b & d) for b in atomic_preds for d in pred2atomic_pred(pred)}
        atomic_preds = {a for a in atomic_preds if not a.is_zero()}

    return list(atomic_preds)

# TODO: This could probably be interleaved with AP construction for perf gain
#       But perf gain currently not worth it.
def decompose_pred(pred: farray, atomic_preds: List[farray]) -> Set[int]:
    """Decomposes a predicate into its component atomic predicates,
        represented by their positions in the array
        
       Inputs:
            pred: Predicate to decompose.
            atomic_preds: List of atomic predicates for decomposition.
        Output:
            Set of integers representing indexes into atomic_preds."""

    indexes: Set[int] = set()
    for i, ap in enumerate(atomic_preds):
        # if ap & pred != empty then add ap's index. ap is in pred
        if not (pred & ap).is_zero():
            indexes.add(i)
    return indexes

def is_representative(preds: Set[farray], repr_preds: List[farray]) -> bool:
    """Is repr_preds a representative set of preds?"""

    is_repr = True
    # Property 1: no empty sets
    for rp in repr_preds:
        is_repr &= not rp.is_zero()
    
    # Property 2: covers entire space
    space = bdd_false
    for rp in repr_preds:
        space |= rp
    is_repr &= space.is_one()

    # Property 3: spaces are disjoint
    for i in range(len(repr_preds) - 1):
        for j in range(i, len(repr_preds)):
            is_repr &= (repr_preds[i] & repr_preds[j]).is_zero()
    
    for p in preds:
        new_p = bdd_false
        for i in decompose_pred(p, repr_preds):
            new_p |= repr_preds[i]
        is_repr &= (p is new_p)

    return is_repr
