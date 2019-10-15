import yaml
import os.path
import ipaddress
from typing import Dict, List, Set

from bddutils import *
from pyeda import farray
from pyeda.boolalg.bdd import bddzeros, bddones

bdd_false = bddzeros(1)[0]
bdd_true = bddones(1)[0]

ws_path = os.path.abspath(os.path.dirname(__file__))
dp_path = os.path.join(ws_path, 'traces/dataplane/sample_dataplane.yml')
with open(dp_path) as f:
    dp = yaml.load(f, Loader=yaml.BaseLoader)

if_dict: Dict[str, int] = {} # dict for interface names
for device in dp['Devices']: # build index for interface names
    if_cnt = 0
    for interface in device['Interfaces']:
        if_dict[interface['Name']] = if_cnt
        if_cnt = if_cnt + 1

acl_dict: Dict[str, int] = {} # dict for acl names
for device in dp['Devices']: # build index for acl names
    acl_cnt = 0
    for acl in device['Acls']:
        acl_dict[acl['Name']] = acl_cnt
        acl_cnt = acl_cnt + 1


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

def ft2preds(forwarding_table, interfaces) -> List[farray]:
    """Algorithm 2
        Converts a forwarding table to predicates.

        Returns:
            A list of forwarding predicates for the device.
            Each predicate corresponds to an interface.
            Ordered by interface index values in if_dict.
    """
    preds = [bdd_false for interface in interfaces] # init with false

    forwarding_table.sort(key=rule_preflen, reverse=True) # longest prefix first
    
    fwd = bdd_false # fwd <- false
    for ft_rule in forwarding_table:
        if_index = if_dict[ft_rule['Interface']]
        prefix = ipp2bdd(ft_rule['Prefix']) # p <- p \/ (prefix /\ ~fwd)
        preds[if_index] = preds[if_index] | (prefix & (~fwd))
        fwd = fwd | prefix # fwd <- fwd \/ prefix
    return preds

#preds = ft2preds(dp['Devices'][1]['ForwardingTable'], dp['Devices'][1]['Interfaces'])
#print(dp['Devices'][1]['ForwardingTable'])
#for pred in preds:
#    print(bdd2expr(pred))
pred = acl2pred(dp['Devices'][3]['Acls'][0])
print(bdd2expr(pred))

# acls = [acl2pred(device['Acls']) 
#     for device in dp['Devices']]
# fts = [ft2preds(device['ForwardingTable'], device['Interfaces']) 
#     for device in dp['Devices']]

