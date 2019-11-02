from typing import Set, List

from bddutils import *
from timeutils import *

# pointers to data structures in main.py
device_dict = {}
interface_dict = {}
pred_dict_acls = {}
pred_dict_fts = {}

# global data structure for dfs
traverse_flags = {}
reachable = []

@timeit
def network_dfs(iport, eport, pred_traffic, dfsn):
    global device_dict
    global interface_dict
    global pred_dict_acls
    global pred_dict_fts
    global traverse_flags
    global reachable

    inbound_acl = interface_dict[iport]['InAcl']
    if  inbound_acl != None:
        pred_traffic &= pred_dict_acls[inbound_acl]

    # Traceback condition 1: No possible header left
    if pred_traffic.is_zero():
        return

    # Traceback condition 2: reach dst device
    in_device_name = iport.split('@')[0]
    dst_device_name = eport.split('@')[0]
    if dst_device_name == in_device_name: 
        # only consider target eport
        outbound_acl = interface_dict[eport]['OutAcl']
        if outbound_acl != None:
            pred_traffic &= pred_dict_acls[outbound_acl]
        pred_traffic &= pred_dict_fts[eport]
        # find a path that eport is reachable
        if not pred_traffic.is_zero():
            reachable.append(pred_traffic)
        return

    traverse_flags[in_device_name] = dfsn

    # find next hop device
    for out_interface in device_dict[in_device_name]['Interfaces']:
        out_interface_name = out_interface['Name']
        #if out_interface_name == iport: # NOTE: assume no backwards forwarding
        #    continue
        next_hop_iport = out_interface['Neighbor']
        if next_hop_iport == None:
            continue

        next_hop_device = next_hop_iport.split('@')[0]
        # Error condition 1: Loop detected
        # FIXME: should raise Exception
        if traverse_flags[next_hop_device] != 0:
            continue

        new_pred_traffic = pred_traffic
        outbound_acl = interface_dict[out_interface_name]['OutAcl']
        if outbound_acl != None:
            new_pred_traffic &= pred_dict_acls[outbound_acl]
        new_pred_traffic &= pred_dict_fts[out_interface_name]

        # dfs recuisive
        network_dfs(next_hop_iport, eport, new_pred_traffic, dfsn + 1)
    
    traverse_flags[in_device_name] = 0
    return

@timeit            
def judge_query(query, _device_dict, _interface_dict,
    _pred_dict_acls, _pred_dict_fts) -> bool:
    """Judgement of a reachability statement

        Search available route from Ingress to Egress via DFS, if multiple routes
        exist, the reachable packets should be the union of allowed packets 
        through all available routes.
        Assumptions:
            Only one Ingress port and one Egress port envolved, though the 
            function can easily be extended to loose this assumption
        Args:
            query: an query instance from YAML file
            OTHERS: related data structure used in the algorithm
        Returns:
            True, if ALL packets injected into Ingress port CAN reach Egress
            False, elsewise
    """
    # initiate pointers to global datastructure
    global device_dict
    global interface_dict
    global pred_dict_acls
    global pred_dict_fts
    device_dict = _device_dict
    interface_dict = _interface_dict
    pred_dict_acls = _pred_dict_acls 
    pred_dict_fts = _pred_dict_fts

    iport = query['Ingress'][0]
    eport = query['Egress'][0]

    qu_pred = qu2pred(query)

    global traverse_flags
    traverse_flags = {
        name:0
        for name,device in device_dict.items() 
    }
    # every reachable path turns out to be a BDD-predicate in reachable[]
    global reachable
    reachable = []
    network_dfs(iport, eport, qu_pred, 1)

    # union of all reachable paths
    reachable_pred = bdd_false
    for pred in reachable:
        reachable_pred |= pred

    # judge: qu_pred is a subset of reachable_pred
    return (~reachable_pred & qu_pred).is_zero()
    