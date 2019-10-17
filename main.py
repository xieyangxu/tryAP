import yaml
import os.path
import ipaddress
from typing import Dict, List

from bddutils import *
from aputils import *
from pyeda.boolalg.bfarray import farray

ws_path = os.path.abspath(os.path.dirname(__file__))
dp_path = os.path.join(ws_path, 'traces/dataplane/sample_dataplane.yml')
with open(dp_path) as f:
    dp = yaml.load(f, Loader=yaml.BaseLoader)

def acl2pred(acl) -> farray:
    """Algorithm 1
        Converts an ACL to a predicate.

        Assume ACL first-match processing.
    """
    allowed = bdd_false # init with false
    denied = bdd_false
    
    for rule in acl['Rules']:
        if rule['Action'] == 'Deny':
            denied = denied | (aclr2bdd(rule) & ~allowed)
        else:
            allowed = allowed | (aclr2bdd(rule) & ~denied)
    if acl['DefaultAction'] == 'Deny':
        return allowed
    else:
        return ~denied


def rule_preflen(ft_rule) -> int: # helper function to sort forwarding table
    ipn = ipaddress.IPv4Network(ft_rule['Prefix'])
    return ipn.prefixlen

def ft2preds(forwarding_table, interfaces) -> Dict[str, farray]:
    """Algorithm 2
        Converts a forwarding table to predicates.

        Returns:
            A dict of forwarding predicates for the device.
            key = interface name
            value = forwarding predicate
    """
    preds = {interface['Name']:bdd_false for interface in interfaces} # init with false

    forwarding_table.sort(key=rule_preflen, reverse=True) # longest prefix first
    
    fwd = bdd_false # fwd <- false
    for ft_rule in forwarding_table:
        if_name = ft_rule['Interface']
        prefix = ipp2bdd(ft_rule['Prefix']) # p <- p \/ (prefix /\ ~fwd)
        preds[if_name] = preds[if_name] | (prefix & (~fwd))
        fwd = fwd | prefix # fwd <- fwd \/ prefix
    return preds

#preds = ft2preds(dp['Devices'][1]['ForwardingTable'], dp['Devices'][1]['Interfaces'])
#print(dp['Devices'][1]['ForwardingTable'])
#for pred in preds:
#    print(bdd2expr(pred))
#pred = acl2pred(dp['Devices'][3]['Acls'][0])
#print(bdd2expr(pred))

pred_dict_acls = {
    acl['Name']:acl2pred(acl) 
    for device in dp['Devices'] for acl in device['Acls']
}
pred_dict_fts = {}
for device in dp['Devices']:
    tmp_dict = ft2preds(device['ForwardingTable'], device['Interfaces'])
    pred_dict_fts.update(tmp_dict)


pred_set_acls = {pred for name,pred in pred_dict_acls.items()}
pred_set_fts = {pred for name,pred in pred_dict_fts.items()}

ap_acls = preds2atomic_preds(pred_set_acls)
ap_fts = preds2atomic_preds(pred_set_fts)

nset_dict_acls = {
    name:decompose_pred(pred, ap_acls)
    for name,pred in pred_dict_acls.items()
}
nset_dict_fts = {
    name:decompose_pred(pred, ap_fts)
    for name,pred in pred_dict_fts.items()
}