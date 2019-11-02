from typing import Dict, List
import ipaddress
from pyeda.boolalg.bdd import bdd2expr
from pyeda.boolalg.bfarray import farray
from pyeda.boolalg.bfarray import bddzeros, bddones, bddvars
from timeutils import *

bdd_false = bddzeros(1)[0]
bdd_true = bddones(1)[0]

#@timeit
def ipp2bdd(ipprefix='0.0.0.0/0', namespace='dip'): # convert a ip prefix to BDD
    ipn = ipaddress.ip_network(ipprefix)
    addr_int = int(ipn.network_address)
    addr = [addr_int >> i & 1 for i in range(31,-1,-1)] # 32-bit vector
    preflen = ipn.prefixlen # prefix length
    
    x = bddvars(namespace, 32)
    f = bddones(1)[0] # init with trivial value f=true

    for i in range(preflen):
        if addr[i]:
            f = f & x[i]
        else:
            f = f & ~x[i]
    
    return f

def less2bdd(v, bitlen, namespace): # BDD version of f(x): x<v?
    f = bddzeros(1)[0] # init with false
    v_bin = [v >> i & 1 for i in range(bitlen-1, -1, -1)] # bit vector

    x = bddvars(namespace, bitlen)
    for i in range(bitlen):
        if v_bin[i]:
            tmp = bddones(1)[0]
            for j in range(i): # 0 ~ i-1
                if v_bin[j]:
                    tmp = tmp & x[j]
                else:
                    tmp = tmp & ~x[j]
            tmp = tmp & ~x[i] # i
            f = f | tmp
    return f

def equal2bdd(v, bitlen, namespace): # BDD version of f(x): x==v?
    f = bddones(1)[0] # init with true
    v_bin = [v >> i & 1 for i in range(bitlen-1, -1, -1)] # bit vector
    
    x = bddvars(namespace, bitlen)
    for i in range(bitlen):
        if v_bin[i]:
            f = f & x[i]
        else:
            f = f & ~x[i]
    return f

#@timeit
def range2bdd(vrange, bitlen, namespace): # BDD version of f(x): x in vrange?
    tmp = vrange.split('-')
    vstart = int(tmp[0])
    vend = int(tmp[1])
    f_equal_to_end = equal2bdd(vend, bitlen, namespace)
    f_less_than_end = less2bdd(vend, bitlen, namespace)
    f_less_than_start = less2bdd(vstart, bitlen, namespace)
    f = f_equal_to_end | (f_less_than_end & ~f_less_than_start)
    return f


def aclr2bdd(acl_rule): # convert an ACL rule to BDD
    # protocol
    f_protocol = range2bdd(acl_rule['Protocol'], 8, 'pro')
    
    # dst ip
    f_dstip = ipp2bdd(acl_rule['DstIp'], 'dip')

    # src ip
    f_srcip = ipp2bdd(acl_rule['SrcIp'], 'sip')

    # dst port
    f_dstport = range2bdd(acl_rule['DstPort'], 16, 'dpt')

    # src port
    f_srcport = range2bdd(acl_rule['SrcPort'], 16, 'spt')

    f = f_protocol & f_dstip & f_srcip & f_dstport & f_srcport
    return f

@timeit
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

#@timeit
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

@timeit
def qu2pred(query) -> farray: # convert a query to a predicate
    # protocol
    f_protocol = bdd_false
    for dip in query['Protocol']:
        f_protocol |= range2bdd(dip, 8, 'pro')
    
    # dst ip
    f_dstip = bdd_false
    for dst in query['DstIp']:
        f_dstip |= ipp2bdd(dst, 'dip')

    # src ip
    f_srcip = bdd_false
    for src in query['SrcIp']:
        f_srcip |= ipp2bdd(src, 'sip')

    # dst port
    f_dstport = bdd_false
    for dpt in query['DstPort']:
        f_dstport |= range2bdd(dpt, 16, 'dpt')

    # src port
    f_srcport = bdd_false
    for spt in query['SrcPort']:
        f_srcport |= range2bdd(spt, 16, 'spt')

    f = f_protocol & f_dstip & f_srcip & f_dstport & f_srcport
    return f

