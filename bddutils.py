import ipaddress
from pyeda.boolalg.bdd import bdd2expr
from pyeda.boolalg.bfarray import bddzeros, bddones, bddvars

bdd_false = bddzeros(1)[0]
bdd_true = bddones(1)[0]

# ipn = ipaddress.ip_network('1.0.0.0/24')
# addr = ipn.network_address.packed
# pref = ipn.prefixlen
# print(ipn.network_address.packed)
# print(ipn.prefixlen)

# x = bddvars('x', 32)
# f = expr2bdd(x[0] & ~x[1])
# print(bdd2expr(f))

# f1 = expr2bdd(~x[0] & ~x[1])
# f = f | f1
# f = expr2bdd(x[0] | ~ x[0])
# print(bdd2expr(f))


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

def range2bdd(vrange, bitlen, namespace): # BDD version of f(x): x in vrange?
    tmp = vrange.split('-')
    vstart = int(tmp[0])
    vend = int(tmp[1])
    f_equal_to_end = equal2bdd(vend, 8, namespace)
    f_less_than_end = less2bdd(vend, 8, namespace)
    f_less_than_start = less2bdd(vstart, 8, namespace)
    f = f_equal_to_end | (f_less_than_end & ~f_less_than_start)
    return f


def aclr2bdd(acl_rule): # convert an ACL rule to BDD
    allowed = bddzeros(1)[0]
    denied = bddzeros(1)[0]

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




if __name__=="__main__":
    #pred = ipp2bdd('70.4.193.0/24')
    #print(bdd2expr(pred))
    f = range2bdd('0-65535', 16, 'pro')
    print(bdd2expr(f))
