import yaml
import os.path
import argparse

from tryAP.bddutils import *
from tryAP.aputils import *
from tryAP.reachability import *
from tryAP.timeutils import *


def main(trace, ws_path):
    dp_path = os.path.join(ws_path, 'traces/dataplane/'+trace+'_dataplane.yml')
    with open(dp_path) as f:
        dp = yaml.load(f, Loader=yaml.SafeLoader)

    qu_path = os.path.join(ws_path, 'traces/query/'+trace+'_query.yml')
    with open(qu_path) as f:
        qu = yaml.load(f, Loader=yaml.SafeLoader)

    # build name dict for devices and interfaces
    device_dict = {
        device['Name']: device
        for device in dp['Devices']
    }
    interface_dict = {
        interface['Name']: interface
        for device in dp['Devices'] for interface in device['Interfaces']
    }

    # convert every ACL to a predicate and build name-predicate dict
    pred_dict_acls = {
        acl['Name']: acl2pred(acl)
        for device in dp['Devices'] for acl in device['Acls']
    }

    # build forwarding predicate for every interface and build name-predicate dict
    pred_dict_fts = {}
    for device in dp['Devices']:
        sub_dict = ft2preds(device['ForwardingTable'], device['Interfaces'])
        pred_dict_fts.update(sub_dict)

    # compute atomic predicates for ACL and FT seperately
    pred_set_acls = {pred for name, pred in pred_dict_acls.items()}
    pred_set_fts = {pred for name, pred in pred_dict_fts.items()}
    # if NO ACL exists: a single 1 predicate is added, enabling trivial tests
    if len(pred_set_acls) == 0:
        pred_set_acls.add(bdd_true)

    ap_acls = preds2atomic_preds(pred_set_acls)
    ap_fts = preds2atomic_preds(pred_set_fts)

    # each predicate is represented as the disjunction of a subset of atomic predicates
    # stored as a set of index
    iset_dict_acls = {
        name: decompose_pred(pred, ap_acls)
        for name, pred in pred_dict_acls.items()
    }
    iset_dict_fts = {
        name: decompose_pred(pred, ap_fts)
        for name, pred in pred_dict_fts.items()
    }

    # Judge reachability statement for every query entry
    for query in qu:
        print(judge_query(query, device_dict, interface_dict, ap_acls, ap_fts,
                          iset_dict_acls, iset_dict_fts))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-d', '--dir', metavar='d', nargs=1, default=os.path.abspath(
        os.path.dirname(__file__)), help='directory to look for traces folder')
    parser.add_argument('trace', metavar='t', type=str, nargs=1,
                        help='trace name. try `sample` or `bistable`')

    args = parser.parse_args()
    trace = args.trace[0]

    # load dataplane and queries from yaml file
    ws_path = os.path.abspath(args.dir[0])
    main(trace, ws_path)
