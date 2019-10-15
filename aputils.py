# functions for atomic predicates


def pred2atomic_pred(pred: farray) -> Set[farray]:
    """Equation 2

    Input: A single predicate.
    Output: Its atomic predicates.
    """
    if pred is bdd_true or pred is bdd_false:
        return {bdd_true}
    else:
        return {pred, ~pred}

def preds2atomic_preds(preds: Set[farray]) -> Set[farray]:
    """Algorithm 3

    Input: A list of predicates.
    Output: A list of atomic predicates.
    """

    for i, pred in enumerate(preds):
        if i == 0:
            atomic_preds = pred2atomic_pred(pred)
        atomic_preds = {(b & d) for b in atomic_preds for d in pred2atomic_pred(pred)}
        atomic_preds = {a for a in atomic_preds if a is not bdd_false}

    return atomic_preds
