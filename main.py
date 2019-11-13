import yaml
import os.path
import copy

from bddutils import *
from reachability import *
from timeutils import *

trace = 'grading'

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
acl_dict = {
    acl['Name']:acl
    for device in dp['Devices'] for acl in device['Acls']
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
for i, query in enumerate(qu):
    print('#%d: %s' % (i+1 , judge_query(query, device_dict, interface_dict, pred_dict_acls, pred_dict_fts)))
    print()

# load acl update
update_path = os.path.join(ws_path, 'traces/dataplane/'+trace+'_dataplane_update.yml')
try:
    with open(update_path) as f:
        update = yaml.load(f, Loader=yaml.SafeLoader)
except IOError as e:
    print('No update file found.')
    exit()
print('---------------- Update file loaded ----------------')

# update original dict
for device in update['Devices']:
    for interface in device['Interfaces']:
        interface_dict[interface['Name']] = copy.deepcopy(interface)
    for acl in device['Acls']:
        acl_dict[acl['Name']] = copy.deepcopy(acl)
        pred_dict_acls[acl['Name']] = acl2pred(acl)

# Judge every query with updated dataplane
for i, query in enumerate(qu):
    print('#%d: %s' % (i , judge_query(query, device_dict, interface_dict, pred_dict_acls, pred_dict_fts)))
    print()
