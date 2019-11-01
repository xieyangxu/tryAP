import yaml
import os.path

from bddutils import *
from reachability import *

trace = 'sample'

# load dataplane and queries from yaml file
ws_path = os.path.abspath(os.path.dirname(__file__))

dp_path = os.path.join(ws_path, 'traces/dataplane/'+trace+'_dataplane.yml')
with open(dp_path) as f:
    dp = yaml.load(f, Loader=yaml.SafeLoader)

qu_path = os.path.join(ws_path, 'traces/query/'+trace+'_query.yml')
with open(qu_path) as f:
    qu = yaml.load(f, Loader=yaml.SafeLoader)

# build name dict for devices and interfaces
device_dict = {
    device['Name']:device
    for device in dp['Devices']
}
interface_dict = {
    interface['Name']:interface
    for device in dp['Devices'] for interface in device['Interfaces']
}

# convert every ACL to a predicate and build name-predicate dict
pred_dict_acls = {
    acl['Name']:acl2pred(acl) 
    for device in dp['Devices'] for acl in device['Acls']
}

# build forwarding predicate for every interface and build name-predicate dict
pred_dict_fts = {}
for device in dp['Devices']:
    sub_dict = ft2preds(device['ForwardingTable'], device['Interfaces'])
    pred_dict_fts.update(sub_dict)

# Judge reachability statement for every query entry
for query in qu:
    print(judge_query(query, device_dict, interface_dict, pred_dict_acls, pred_dict_fts))