import os
import copy
import pytest
import re
import json
import difflib
import string
import random
from utilities import parallel

from spytest import st, tgapi, SpyTestDict
from spytest.utils import filter_and_select
from utilities.utils import retry_api

import apis.common.asic as asicapi
import apis.switching.vlan as vapi
import apis.routing.ip as ipfeature
import apis.switching.mac as macapi
import apis.system.reboot as reboot
import apis.system.port as papi
import apis.system.interface as intfapi
import apis.routing.bgp as bgp_api
import apis.routing.arp as arp_obj
import apis.routing.bfd as bfdapi
import apis.routing.ip_bgp as ip_bgp
from apis.common import redis

from esr_vars import * #all the variables used for vrf testcase
from esr_vars import data

def precheck_bgp_isolate(dut):

    cmd = "cli -c 'no page' -c 'show isolated_precheck'"
    output = st.show(dut, cmd)
    if len(output) == 0:
        st.error("Show OUTPUT is Empty")
        st.report_fail("bgp isolate precheck failed")

    for i in range(len(output)):
        if output[i]['precheck'] != 'success':
            st.error("vrf {} neighbor {} pre check failed".format(output[i]['vrf'],output[i]['neighbor']))
            return False
    
    return True

def check_bgp_isolate(dut, check_status):

    cmd = "cli -c 'no page' -c 'show isolated_bgp'"
    output = st.show(dut,cmd)
    if len(output) == 0:
        st.error("Show OUTPUT is Empty")
        st.report_fail("bgp isolate failed")

    for i in range(len(output)):
        if output[i]['status'] != check_status:
            st.error("vrf {} neighbor {} isolate failed".format(output[i]['vrf'],output[i]['neighbor']))
            return False
    
    return True


def bgp_permit_route_map_set(dut, local_as_id, vrf, group_name, map_name, as_path, config='yes'):

    command = "route-map {} permit 10\n".format(map_name)
    command += "set as-path prepend {}\n".format(as_path)
    command += "exit\n"
    command += "router bgp {} vrf {}\n".format(local_as_id, vrf)
    command += " address-family ipv4 unicast\n"
    if config == 'yes':
        command += "neighbor {} route-map {} out\n".format(group_name, map_name)
    else:
        command += "no neighbor {} route-map {} out\n".format(group_name, map_name)
    command += "exit\n"
    command += " address-family ipv6 unicast\n"
    group_v6_name = group_name + "-v6"
    if config == 'yes':
        command += "neighbor {} route-map {} out\n".format(group_v6_name, map_name)
    else:
        command += "no neighbor {} route-map {} out\n".format(group_v6_name, map_name)
    command += "exit\n"
    command += "exit\n"
    st.config(dut, command, skip_error_check=True, type='alicli')


def bgp_deny_route_map_apply(dut, local_as_id, vrf, group_name, map_name, config='yes'):

    command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
    command += " address-family ipv4 unicast\n"
    if config == 'yes':
        command += "neighbor {} route-map {} out\n".format(group_name, map_name)
    else:
        command += "no neighbor {} route-map {} out\n".format(group_name, map_name)
    command += "exit\n"
    command += " address-family ipv6 unicast\n"
    group_v6_name = group_name + "-v6"
    if config == 'yes':
        command += "neighbor {} route-map {} out\n".format(group_v6_name, map_name)
    else:
        command += "no neighbor {} route-map {} out\n".format(group_v6_name, map_name)
    command += "exit\n"
    command += "exit\n"
    st.config(dut, command, skip_error_check=True, type='alicli')

def bgp_maximum_paths_set(dut, local_as_id, vrf, max_paths_num='64', config='yes'):

    command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
    command += " address-family ipv4 unicast\n"
    if config == 'yes':
        command += "maximum-paths {}\n".format(max_paths_num)
    else:
        command += "no maximum-paths\n"
    command += "exit\n"
    command += " address-family ipv6 unicast\n"
    if config == 'yes':
        command += "maximum-paths {}\n".format(max_paths_num)
    else:
        command += "no maximum-paths\n"
    command += "exit\n"
    st.config(dut, command, skip_error_check=True, type='alicli')
    
def dut_load_bgp_ecmp_member(dut, local_as_id, nbr_as_id, vrf, ip_intf_list, ecmp_member_num, group_name, config='yes'):
    vrf_ip_list=[]
    vrf_ipv6_list=[]
    ecmp_scale_subintf_list = []

    for i in range(ecmp_member_num):
        subintf = int(data.dut_ecmp_scale_start_subintf) + i
        ecmp_scale_subintf_list.append(str(subintf))

    for ip in ip_intf_list:
        if ip['vrf'] == vrf and ip['interface'].startswith('Eth'):
            if ip['interface'].split('.')[1] in ecmp_scale_subintf_list:
                if ':' not in ip['ip']:
                    vrf_ip_list.append(ip['ip'].split('/')[0])
                else:
                    vrf_ipv6_list.append(ip['ip'].split('/')[0])

    dut_load_bgp_neigbor_to_peer_group(dut, local_as_id, nbr_as_id, vrf, vrf_ip_list, vrf_ipv6_list, group_name, config)

def dut_load_bgp_neigbor_to_peer_group(dut, local_as_id, nbr_as_id, vrf, vrf_ip_list, vrf_ipv6_list, group_name, config='yes'):
    if config == 'yes':
        command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        command += "neighbor {} peer-group\n".format(group_name)
        command += "neighbor {} remote-as {}\n".format(group_name, nbr_as_id)
        for ip in vrf_ip_list:
            command += "neighbor {} peer-group {}\n".format(ip, group_name)
        command += " address-family ipv4 unicast\n"
        command += "neighbor {} activate\n".format(group_name)
        command += "neighbor {} soft-reconfiguration inbound\n".format(group_name)
        command += "exit\n"
        command += "exit\n"
        st.config(dut, command, skip_error_check=True, type='alicli')

        command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        ipv6_group_name =  group_name + "-v6"
        command += "neighbor {} peer-group\n".format(ipv6_group_name)
        command += "neighbor {} remote-as {}\n".format(ipv6_group_name, nbr_as_id)
        for ip in vrf_ipv6_list:
            command += "neighbor {} peer-group {}\n".format(ip, ipv6_group_name)
        command += " address-family ipv6 unicast\n"
        command += "neighbor {} activate\n".format(ipv6_group_name)
        command += "neighbor {} soft-reconfiguration inbound\n".format(ipv6_group_name)
        command += "exit\n"
        command += "exit\n"
        st.config(dut, command, skip_error_check=True, type='alicli')

        st.show(dut,"show vrf")

        #command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        #command += "bgp bestpath compare-routerid\n"
        #st.config(dut, command, skip_error_check=True, type='vtysh')
    elif config == 'no':
        command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        for ip in vrf_ipv6_list:
            command += "no neighbor {} peer-group\n".format(ip)
        for ip in vrf_ip_list:
            command += "no neighbor {} peer-group\n".format(ip)
        command += "exit\n"
        st.config(dut, command, skip_error_check=True, type='alicli')

        st.show(dut,"show vrf")

def dut_load_bgp_isolate_peer_group(dut, local_as_id, nbr_as_id, vrf, nbr_ip_list, config='yes'):
    vrf_ip_list=[]
    vrf_ipv6_list=[]
    ecmp_scale_subintf_list = []

    for i in range(data.dut_isolate_group_num):
        subintf = int(data.dut_ecmp_scale_start_subintf) + i
        ecmp_scale_subintf_list.append(str(subintf))

    for ip in nbr_ip_list:
        if ip['vrf'] == vrf and ip['interface'].startswith('Eth'):
            if ip['interface'].split('.')[1] in ecmp_scale_subintf_list:
                if ':' not in ip['ip']:
                    vrf_ip_list.append(ip['ip'].split('/')[0])
                else:
                    vrf_ipv6_list.append(ip['ip'].split('/')[0])

    if config == 'yes':
        command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        groupid =0
        for ip in vrf_ip_list:
            group_name = 'isolate_' + str(groupid)
            groupid += 1
            command += "neighbor {} peer-group {}\n".format(ip, group_name)
        command += "exit\n"
        st.config(dut, command, skip_error_check=True, type='alicli')

        command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        groupid =0
        for ip in vrf_ipv6_list:
            group_name = 'isolate_v6_' + str(groupid)
            groupid += 1
            command += "neighbor {} peer-group {}\n".format(ip, group_name)
        command += "exit\n"
        st.config(dut, command, skip_error_check=True, type='alicli')
    elif config == 'no':
        command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        for ip in vrf_ip_list:
            command += "no neighbor {} peer-group\n".format(ip)
        command += "exit\n"
        st.config(dut, command, skip_error_check=True, type='alicli')

        command = "router bgp {} vrf {}\n".format(local_as_id, vrf)
        for ip in vrf_ipv6_list:
            command += "no neighbor {} peer-group\n".format(ip)
        command += "exit\n"
        st.config(dut, command, skip_error_check=True, type='alicli')

    st.show(dut, "show vrf")

def cli_show_json(dut, command, type='alicli'):
    output = st.show(dut, command, max_time=500, skip_error_check=True, skip_tmpl=True, type=type)
    json_str = json.dumps(output).encode('utf-8')
    last_pos = json_str.rfind('}')
    json_str = json_str[:(last_pos+1)].replace('true','"true"').replace("\\n","").replace("\\","").strip('"')
    try:
        return json.loads(json_str)
    except ValueError:
        st.log('cli_show_json: failed to convert json output')
        return {}

class json_cmp_result(object):
    "json_cmp result class for better assertion messages"

    def __init__(self):
        self.errors = []

    def add_error(self, error):
        "Append error message to the result"
        for line in error.splitlines():
            self.errors.append(line)

    def has_errors(self):
        "Returns True if there were errors, otherwise False."
        return len(self.errors) > 0

    def __str__(self):
        return '\n'.join(self.errors)

def get_textdiff(text1, text2, title1="", title2="", **opts):
    "Returns empty string if same or formatted diff"

    diff = '\n'.join(difflib.unified_diff(text1, text2,
           fromfile=title1, tofile=title2, **opts))
    # Clean up line endings
    diff = os.linesep.join([s for s in diff.splitlines() if s])
    return diff

def difflines(text1, text2, title1='', title2='', **opts):
    "Wrapper for get_textdiff to avoid string transformations."
    text1 = ('\n'.join(text1.rstrip().splitlines()) + '\n').splitlines(1)
    text2 = ('\n'.join(text2.rstrip().splitlines()) + '\n').splitlines(1)
    return get_textdiff(text1, text2, title1, title2, **opts)

def json_diff(d1, d2):
    """
    Returns a string with the difference between JSON data.
    """
    json_format_opts = {
        'indent': 4,
        'sort_keys': True,
    }
    dstr1 = json.dumps(d1, **json_format_opts)
    dstr2 = json.dumps(d2, **json_format_opts)
    return difflines(dstr2, dstr1, title1='Expected value', title2='Current value', n=0)

def _json_list_cmp(list1, list2, parent, result):
    "Handles list type entries."
    # Check second list2 type
    if not isinstance(list1, type([])) or not isinstance(list2, type([])):
        result.add_error(
            '{} has different type than expected '.format(parent) +
            '(have {}, expected {}):\n{}'.format(
                type(list1), type(list2), json_diff(list1, list2)))
        return

    # Check list size
    if len(list2) > len(list1):
        result.add_error(
            '{} too few items '.format(parent) +
            '(have {}, expected {}:\n {})'.format(
                len(list1), len(list2),
                json_diff(list1, list2)))
        return

    # List all unmatched items errors
    unmatched = []
    for expected in list2:
        matched = False
        for value in list1:
            if json_cmp({'json': value}, {'json': expected}) is None:
                matched = True
                break

        if not matched:
            unmatched.append(expected)

    # If there are unmatched items, error out.
    if unmatched:
        result.add_error(
            '{} value is different (\n{})'.format(
                parent, json_diff(list1, list2)))

def json_cmp(d1, d2):
    """
    JSON compare function. Receives two parameters:
    * `d1`: json value
    * `d2`: json subset which we expect

    Returns `None` when all keys that `d1` has matches `d2`,
    otherwise a string containing what failed.

    Note: key absence can be tested by adding a key with value `None`.
    """
    squeue = [(d1, d2, 'json')]
    result = json_cmp_result()

    for s in squeue:
        nd1, nd2, parent = s

        # Handle JSON beginning with lists.
        if isinstance(nd1, type([])) or isinstance(nd2, type([])):
            _json_list_cmp(nd1, nd2, parent, result)
            if result.has_errors():
                return result
            else:
                return None

        # Expect all required fields to exist.
        s1, s2 = set(nd1), set(nd2)
        s2_req = set([key for key in nd2 if nd2[key] is not None])
        diff = s2_req - s1
        if diff != set({}):
            result.add_error('expected key(s) {} in {} (have {}):\n{}'.format(
                str(list(diff)), parent, str(list(s1)), json_diff(nd1, nd2)))

        for key in s2.intersection(s1):
            # Test for non existence of key in d2
            if nd2[key] is None:
                result.add_error('"{}" should not exist in {} (have {}):\n{}'.format(
                    key, parent, str(s1), json_diff(nd1[key], nd2[key])))
                continue

            # If nd1 key is a dict, we have to recurse in it later.
            if isinstance(nd2[key], type({})):
                if not isinstance(nd1[key], type({})):
                    result.add_error(
                        '{}["{}"] has different type than expected '.format(parent, key) +
                        '(have {}, expected {}):\n{}'.format(
                            type(nd1[key]), type(nd2[key]), json_diff(nd1[key], nd2[key])))
                    continue
                nparent = '{}["{}"]'.format(parent, key)
                squeue.append((nd1[key], nd2[key], nparent))
                continue

            # Check list items
            if isinstance(nd2[key], type([])):
                _json_list_cmp(nd1[key], nd2[key], parent, result)
                continue

            # Compare JSON values
            if nd1[key] != nd2[key]:
                result.add_error(
                    '{}["{}"] value is different (\n{})'.format(
                        parent, key, json_diff(nd1[key], nd2[key])))
                continue

    if result.has_errors():
        return result

    return None

## check config db 
def configdb_checkpoint(dut, key, checkfield, checkval, expect = True, checkpoint = ''):
    command = redis.build(dut, redis.CONFIG_DB, 'hgetall "{}"'.format(key))
    output = st.show(dut, command)
    st.log(output)

    redis_cfg_checkpoint = False
    exist = False
    redis_cfg_exist_checkpoint = False if exist else True
    for i in range(len(output)):
        if output[i].get('donor_intf') == checkfield:
            exist = True
            if i+1 < len(output):
                if output[i+1].get('donor_intf') == checkval:
                    redis_cfg_checkpoint = True
            
    if checkval == 'null':
        redis_cfg_exist_checkpoint = False if exist else True
        if redis_cfg_exist_checkpoint != expect:
            st.report_fail("{} confg DB has {} config".format(checkpoint, checkfield))  
    else:
        if redis_cfg_checkpoint != expect:
            st.report_fail("{} confg DB has no right {} config".format(checkpoint, checkfield))

## check config db 
def configdb_onefield_checkpoint(dut, key, checkfield, checkval, expect = True, checkpoint = ''):
    command = redis.build(dut, redis.CONFIG_DB, 'hget "{}" "{}"'.format(key, checkfield))
    output = st.show(dut, command, skip_tmpl=True)
    if output is '':
        st.report_fail("{} confg DB has no right filed {}".format(checkpoint, checkfield))

    output = output.strip('"')
    last_pos = output.rfind('"')
    output = output[:last_pos]
    st.log(output)
    st.log(checkval)
    check = (checkval == output)
    st.log(check)

    if expect is not check:
        st.report_fail("{} confg DB has no right {} config".format(checkpoint, checkfield))

## check config db
def configdb_checkarray(dut, key, checkfield, checkval, expect = True, checkpoint = ''):
    command = redis.build(dut, redis.CONFIG_DB, 'hgetall "{}"'.format(key))
    output = st.show(dut, command)
    st.log(output)

    redis_cfg_checkpoint = False
    exist = False
    for i in range(len(output)):
        if output[i].get('donor_intf') == checkfield:
            exist = True
            if i+1 < len(output):
                vals = output[i+1].get('donor_intf').split(",")
                if checkval in vals:
                    redis_cfg_checkpoint = True

    if redis_cfg_checkpoint != expect:
        st.report_fail("{} confg DB has no right {} config".format(checkpoint, checkfield))

def appdb_checkpoint(dut, key, checkfield, checkval, expect = True, checkpoint = ''):
    command = redis.build(dut, redis.APPL_DB, 'hgetall "{}"'.format(key))
    output = st.show(dut, command)
    st.log(output)

    redis_cfg_checkpoint = False
    exist = False
    redis_cfg_exist_checkpoint = False if exist else True
    for i in range(len(output)):
        if output[i].get('donor_intf') == checkfield:
            exist = True
            if i+1 < len(output):
                if output[i+1].get('donor_intf') == checkval:
                    redis_cfg_checkpoint = True
            
    if checkval == 'null':
        redis_cfg_exist_checkpoint = False if exist else True
        if redis_cfg_exist_checkpoint != expect:
            st.report_fail("{} confg DB has {} config".format(checkpoint, checkfield))  
    else:
        if redis_cfg_checkpoint != expect:
            st.report_fail("{} confg DB has no right {} config".format(checkpoint, checkfield))

def appdb_onefield_checkpoint(dut, key, checkfield, checkval, expect = True, checkpoint = ''):
    command = redis.build(dut, redis.APPL_DB, 'hget "{}" "{}"'.format(key, checkfield))
    output = st.show(dut, command, skip_tmpl=True)
    if output is '':
        st.report_fail("{} app DB has no right filed {}".format(checkpoint, checkfield))

    output = output.strip('"')
    last_pos = output.rfind('"')
    output = output[:last_pos]
    st.log(output)
    st.log(checkval)
    check = (checkval == output)
    st.log(check)

    if expect is not check:
        st.report_fail("{} app DB has no right {} config".format(checkpoint, checkfield))

def appdb_get_onefield(dut, key, field):
    command = redis.build(dut, redis.APPL_DB, 'hget "{}" "{}"'.format(key, field))
    output = st.show(dut, command, skip_tmpl=True)
    if output is '' or output.startswith('(nil)'):
        return None

    output = output.strip('"')
    last_pos = output.rfind('"')
    output = output[:last_pos]
    st.log(output)
    return output

def appdb_get_onefield_route_related(dut, route_key, field):
    ret = ""
    if field in ['nexthop', 'ifname', 'seg_src', 'segment']:
        nexthop_group = appdb_get_onefield(dut, route_key, 'nexthop_group')
        if nexthop_group and nexthop_group != "na":
            nhg_key = 'NEXTHOP_GROUP_TABLE:' + nexthop_group
            nexthop_group_field = appdb_get_onefield(dut, nhg_key, "nexthop_group")
            if nexthop_group_field and nexthop_group_field != "na": # recursive
                nhgs = nexthop_group_field.split(",")
                for idx in range(len(nhgs)):
                    if idx:
                        ret += ","
                    nhg_key_2 = 'NEXTHOP_GROUP_TABLE:' + nhgs[idx]
                    subRet = appdb_get_onefield(dut, nhg_key_2, field)
                    if subRet is None:
                        return None
                    ret += subRet
                return ret
            else:
                return appdb_get_onefield(dut, nhg_key, field)
    elif field in ['vpn_sid']:
        pic_group = appdb_get_onefield(dut, route_key, 'pic_context_id')
        if pic_group and pic_group != "na":
            pic_key = 'PIC_CONTEXT_TABLE:' + pic_group
            pic_group_field = appdb_get_onefield(dut, pic_key, "pic_group")
            if pic_group_field and pic_group_field != "na": # recursive
                pics = pic_group_field.split(",")
                for idx in range(len(pics)):
                    if idx:
                        ret += ","
                    pic_key_2 = 'PIC_CONTEXT_TABLE:' + pics[idx]
                    subRet = appdb_get_onefield(dut, pic_key_2, field)
                    if subRet is None:
                        return None
                    ret += subRet
                return ret
            else:
                return appdb_get_onefield(dut, pic_key, field)
    return appdb_get_onefield(dut, route_key, field)

## check vrf leran route nums
# show ip route vrf VRFNAME summary
# compare: 1 more than or equal , 0 equal, -1 less than

# show ip route vrf Vrf29 summary
# Route Source         Routes               FIB  (vrf Vrf10050)
# connected            1                    1                    
# static               1                    1                    
# ------
# Totals               2                    2                    
# Totals - Dataplane   N/A                  2                    
 
# [{u'fib_ibgp': '', u'total': '2', u'fib_static': '1', u'fib_ebgp': '', u'ibgp': '', u'ebgp': '', 
# u'vrf': 'Vrf10050', u'fib_connected': '1', u'static': '1', u'fib_ospf': '', u'connected': '1', u'ospf': '', u'fib_total': '2'}]
#def check_vrf_route_nums(dut, vrfname, expected_num, compare):
#    cmd = "show ip route vrf {} summary".format(vrfname)
#    result = st.show(dut, cmd, type='alicli')
#    st.log(result)

#    if result is not None:
#        totals = result[0]['fib_total']
#        if totals.isdigit():
#            totals_num = string.atoi(totals)
#            if totals_num >= expected_num and compare==1:
#                return True
#            elif totals_num == expected_num and compare==0:
#                return True
#            elif totals_num < expected_num and compare==-1:
#                return True
#            else:
#                st.log("totals fib num is {} , expected is {}".format(totals_num, expected_num))
#                return False
#    return False



def check_vrf_route_nums(dut, vrfname, expected_num, compare):
    """
    Check VRF route numbers using vtysh with robust parsing.

    Args:
        dut: Device under test
        vrfname: VRF name to check
        expected_num: Expected number of routes
        compare: Comparison mode (1: >=, 0: ==, -1: <)

    Returns:
        bool: True if comparison passes, False otherwise
    """
    cmd = "show ip route vrf {} summary".format(vrfname)
    st.log("Checking VRF {} route count with command: {}".format(vrfname, cmd))

    try:
        # Try vtysh first for more reliable output
        output = st.show(dut, cmd, skip_tmpl=True, max_time=500, type='vtysh')
        if not output:
            st.log("No output from vtysh, trying alicli")
            result = st.show(dut, cmd, type='alicli')
            if result:
                output = str(result)

        st.log("Raw command output: {}".format(output))

        # Extract route count using robust regex patterns
        totals_num = None

        # Pattern 1: Look for "Totals" line with FIB count
        # Example: "Totals               2                    2"
        totals_match = re.search(r'Totals\s+\d+\s+(\d+)', str(output), re.IGNORECASE)
        if totals_match:
            totals_num = int(totals_match.group(1))
            st.log("Found FIB total using Totals pattern: {}".format(totals_num))

        # Pattern 2: Look for "Totals - Dataplane" line
        # Example: "Totals - Dataplane   N/A                  2"
        if totals_num is None:
            dataplane_match = re.search(r'Totals\s*-\s*Dataplane\s+\S+\s+(\d+)', str(output), re.IGNORECASE)
            if dataplane_match:
                totals_num = int(dataplane_match.group(1))
                st.log("Found FIB total using Dataplane pattern: {}".format(totals_num))

        # Pattern 3: Parse alicli structured output if available
        if totals_num is None and isinstance(output, list) and len(output) > 0:
            try:
                if 'fib_total' in output[0]:
                    fib_total_str = output[0]['fib_total']
                    if fib_total_str and fib_total_str.isdigit():
                        totals_num = int(fib_total_str)
                        st.log("Found FIB total from alicli fib_total: {}".format(totals_num))
            except (KeyError, IndexError, TypeError, ValueError) as e:
                st.log("Error parsing alicli output: {}".format(str(e)))

        # Pattern 4: General number extraction as fallback
        if totals_num is None:
            numbers = re.findall(r'\b(\d+)\b', str(output))
            if numbers:
                # Look for the last significant number (often the FIB total)
                for num_str in reversed(numbers):
                    try:
                        num = int(num_str)
                        if num > 0:  # Skip zeros which are often not the total
                            totals_num = num
                            st.log("Using fallback number extraction: {}".format(totals_num))
                            break
                    except ValueError:
                        continue

        if totals_num is None:
            st.log("Could not extract route count from output")
            return False

        st.log("VRF {} FIB route count: {}, expected: {}, compare mode: {}".format(
            vrfname, totals_num, expected_num, compare))

        # Perform comparison based on mode
        if compare == 1:  # greater than or equal
            result = totals_num >= expected_num
        elif compare == 0:  # equal
            result = totals_num == expected_num
        elif compare == -1:  # less than
            result = totals_num < expected_num
        else:
            st.log("Invalid compare mode: {}".format(compare))
            return False

        if result:
            st.log("VRF route count check PASSED")
        else:
            st.log("VRF route count check FAILED: {} vs expected {}".format(totals_num, expected_num))

        return result

    except Exception as e:
        st.log("Exception in check_vrf_route_nums: {}".format(str(e)))
        return False


#def check_vpn_route_nums(dut, expected_num, compare):
#    cmd = "show bgp ipv4 vpn statistics"
#    result = st.show(dut, cmd, type='alicli')
#    st.log(result)
#
#    if result is not None:
#        totals = result[0]['totaladv']
#        if totals.isdigit():
#            totals_num = string.atoi(totals)
#            if totals_num >= expected_num and compare==1:
#                return True
#            elif totals_num == expected_num and compare==0:
#                return True
#            elif totals_num < expected_num and compare==-1:
#                return True
#            else:
#                st.log("totals adv route num is {} , expected is {}".format(totals_num, expected_num))
#                return False
#    return False
def check_vpn_route_nums(dut, expected_num, compare):
    """
    Check VPN route numbers using vtysh with robust number extraction

    Args:
        dut: Device under test
        expected_num: Expected number of routes
        compare: Comparison type (1: >=, 0: ==, -1: <)

    Returns:
        bool: True if condition matches, False otherwise
    """
    cmd = "show bgp ipv4 vpn statistics"
    result = st.show(dut, cmd, type='vtysh', skip_tmpl=True, skip_error_check=True)
    st.log("VPN route statistics output: {}".format(result))

    if result is None or result == "":
        st.log("No output from BGP VPN statistics command")
        return False

    try:
        # Extract numbers from the output using robust method
        numbers = re.findall(r'\d+', str(result))

        if not numbers:
            st.log("No numbers found in BGP VPN statistics output")
            return False

        # For BGP VPN statistics, we typically want the total advertised routes
        # This might be the first or last number depending on output format
        # Try to find patterns like "Total: 123" or "Advertised: 456"

        totals_num = 0

        # Method 1: Look for specific patterns in the output
        total_match = re.search(r'[Tt]otal[^:]*:\s*(\d+)', str(result))
        if total_match:
            totals_num = int(total_match.group(1))
            st.log("Found total routes using pattern match: {}".format(totals_num))
        else:
            # Method 2: Look for advertised routes pattern
            adv_match = re.search(r'[Aa]dvertised[^:]*:\s*(\d+)', str(result))
            if adv_match:
                totals_num = int(adv_match.group(1))
                st.log("Found advertised routes using pattern match: {}".format(totals_num))
            else:
                # Method 3: Use the last number found (common in summary outputs)
                totals_num = int(numbers[-1])
                st.log("Using last number found in output: {}".format(totals_num))

        # Perform the comparison
        if compare == 1 and totals_num >= expected_num:
            st.log("VPN route count {} >= expected {} - PASS".format(totals_num, expected_num))
            return True
        elif compare == 0 and totals_num == expected_num:
            st.log("VPN route count {} == expected {} - PASS".format(totals_num, expected_num))
            return True
        elif compare == -1 and totals_num < expected_num:
            st.log("VPN route count {} < expected {} - PASS".format(totals_num, expected_num))
            return True
        else:
            st.log("VPN route count {} does not match expected {} with comparison {} - FAIL".format(
                totals_num, expected_num, compare))
            return False

    except (ValueError, IndexError, AttributeError) as e:
        st.log("Error parsing VPN route statistics: {}".format(str(e)))
        st.log("Raw output was: {}".format(str(result)[:200]))
        return False

def get_random_array(start, end, num):
    ra = []
    for i in range(num):
        x = random.randint(start, end)
        ra.append(x)
    st.log(ra)
    return ra

def check_bgp_vrf_ipv4_uni_sid(dut, vrf, prefix, expected_sid):
    #cmd = "cli -c 'no page' -c 'show bgp vrf {} ipv4 unicast {}'".format(vrf, prefix)
    cmd = "show bgp vrf {} ipv4 unicast {}".format(vrf, prefix)
    result = st.show(dut, cmd, type='vtysh')
    #result = st.show(dut, cmd)
    st.log(result)

    if result is not None and len(result) > 0:
        for e in result:
            sid = e['sid']
            if sid == expected_sid:
                st.log("sid check right {}".format(sid))
                return True
            else:
                st.log("sid is {} , expected_sid is {}".format(sid, expected_sid))
                # return False
    return False

def get_vrf_realname(dut, alias_name):
    vrf_name = st.show(dut, "vrfnametodevname {}".format(alias_name), skip_tmpl=True, max_time=500, type="vtysh")
    last_pos = vrf_name.rfind('\n')
    vrf_name = vrf_name[:last_pos]
    return vrf_name

def compare_redistribute_vrf_route(vrf1, vrf2, info1, info2):
    infos_1 = info1.splitlines()
    infos_2 = info2.splitlines()
    if len(infos_1) != len(infos_2):
        return False
    if len(infos_1) < 4:
        return False
    for i in range(len(infos_1) - 3):
        st.log(i)
        st.log(infos_1[i])
        st.log(infos_2[i])
        if i == 0 :
            continue
        elif i == 1 :
            infos_2_new = infos_2[i].replace(vrf2, vrf1)
            if infos_1[i] != infos_2_new:
                return False
        else:
            if infos_1[i] != infos_2[i]:
                return False
    return True

def flap_lag_member(dut, lag, flap_count):
    members = data.dut_lag[lag]
    num = len(members)
    if num <= 1:
        return
    
    idx = random.randint(1,128) % num

    for i in range(flap_count):
        phyif = members[idx]
        cmd = "interface {}\n shutdown\n".format(phyif)
        st.config(dut, cmd, type='alicli',skip_error_check=True)
        st.wait(5)
        cmd = "interface {}\n no shutdown\n".format(phyif)
        st.config(dut, cmd, type='alicli',skip_error_check=True)
        st.wait(5)

def show_hw_route_count(dut):
    def_v4_route_count = asicapi.get_ipv4_route_count(dut)
    st.log("{} v4 route : {}".format(dut, def_v4_route_count))
    def_v6_route_count = asicapi.get_ipv6_route_count(dut)
    st.log("{} v6 route : {}".format(dut, def_v6_route_count))

def get_kernel_ip_route(dut, number):
    command = "ip route show vrf Vrf{}| wc -l".format(number)
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True)
    x = re.findall(r"\d+", output)
    if x:
        return int(x[0])
    else:
        return 0

def get_kernel_ipv6_route(dut, number):
    command = "ip -6 route show vrf Vrf{}| wc -l".format(number)
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True)
    x = re.findall(r"\d+", output)
    if x:
        return int(x[0])
    else:
        return 0

def intf_traffic_stats(entry_tx):
    for i in entry_tx:
        p_txmt = i['tx_bps']
        p_txmt = p_txmt.replace(" Gb/s","")
        p_txmt = p_txmt.replace(" Mb/s","")
        p_txmt = p_txmt.replace(" Kb/s","")
        p_txmt = p_txmt.replace(" b/s","")

    p_tx = abs(int(float(p_txmt)))
    return p_tx
def check_dut_intf_tx_traffic_counters(dut, portlist, expect_val):
    papi.clear_interface_counters(dut)
    st.wait(5)
    output = papi.get_interface_counters_all(dut)
    retry = 0
    while len(output) == 0 and retry < 10:
        output = papi.get_interface_counters_all(dut)
        retry += 1
        st.wait(2)
    if retry == 10:
        st.error("Error: Dut port stats")
        return False

    tx_bps_list = []
    for port in portlist:
        tx_bps = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': port}))
        tx_bps_list.append(tx_bps)

    st.log("Inter Dut port stats  tx_ok counter value on DUT Egress ports : {} expect: {}".format(tx_bps_list,expect_val))

    for tx_bps in tx_bps_list:
        if tx_bps == 0:
            st.error("Error:Inter Dut port stats tx_ok counter value on DUT Egress port: {}".format(tx_bps))
            return False
        else:
            deviation = abs(expect_val - tx_bps)
            percent = (float(deviation)/expect_val)*100
            if percent > 10:
                st.log("Inter Dut port stats tx_ok counter value on DUT Egress ports {}".format(tx_bps))
                return False

    st.log("All ECMP paths are utilized")
    return True

def check_mult_dut_intf_tx_traffic_counters(dut, portlist, expect_val):
    total_tx_bps = 0
    papi.clear_interface_counters(dut)
    st.wait(5)
    output = papi.get_interface_counters_all(dut)
    retry = 0
    while len(output) == 0 and retry < 10:
        output = papi.get_interface_counters_all(dut)
        retry += 1
        st.wait(2)
    if retry == 10:
        st.error("Error: Dut port stats")
        return False

    tx_bps_list = []
    for port in portlist:
        tx_bps = intf_traffic_stats(filter_and_select(output, ["tx_bps"], {'iface': port}))
        tx_bps_list.append(tx_bps)
        total_tx_bps += tx_bps

    st.log("Inter Dut port stats  tx_ok counter value on DUT Egress ports : {} expect: {}".format(tx_bps_list,expect_val))

    if total_tx_bps == 0:
        st.error("Error:Inter Dut port stats tx_ok counter value on DUT Egress port: {}".format(tx_bps))
        return False

    deviation = abs(expect_val - total_tx_bps)
    percent = (float(deviation)/expect_val)*100
    if percent > 10:
        st.log("Inter Dut port stats tx_ok counter value on DUT Egress ports {}".format(total_tx_bps))
        return False

    st.log("All ECMP paths are utilized")
    return True

def intf_traffic_stats_percentage(entry_tx):
    for i in entry_tx:
        p_txmt = i['tx_util']
        p_txmt = p_txmt.replace("%","")

    p_tx = abs(int(float(p_txmt)))
    return p_tx

def check_dut_intf_tx_traffic_percentage(dut, portlist, expect_val):
    papi.clear_interface_counters(dut)
    st.wait(5)
    output = papi.get_interface_counters_all(dut)
    retry = 0
    while len(output) == 0 and retry < 10:
        output = papi.get_interface_counters_all(dut)
        retry += 1
        st.wait(2)
    if retry == 10:
        st.error("Error: Dut port stats")
        return False

    tx_util_list = []
    for port in portlist:
        tx_util = intf_traffic_stats_percentage(filter_and_select(output, ["tx_util"], {'iface': port}))
        tx_util_list.append(tx_util)

    st.log("Inter Dut port stats tx_util counter value on DUT Egress ports : {} expect: {}".format(tx_util_list,expect_val))

    for tx_util in tx_util_list:
        if expect_val <= 10:
            deviation = abs(expect_val - tx_util)
            if deviation > 1:
                st.log("Inter Dut port stats tx_util counter value on DUT Egress ports {}".format(tx_util))
                return False
        else:
            deviation = abs(expect_val - tx_util)
            percent = (float(deviation)/expect_val)*100
            if percent > 10:
                st.log("Inter Dut port stats tx_util counter value on DUT Egress ports {}".format(tx_util))
                return False

    return True


def get_bfd_uptime_sec(output):
    uptime = 0
    uptime_day = 0
    uptime_hour = 0
    uptime_min = 0
    uptime_sec = 0
    if 'status' in output and output['status'] == 'up':
        uptime_day = 0 if output.get('uptimeday') == '' else int(output.get('uptimeday'))
        uptime_hour= 0 if output.get('uptimehr') == '' else int(output.get('uptimehr'))
        uptime_min= 0 if output.get('uptimemin') == '' else int(output.get('uptimemin'))
        uptime_sec= 0 if output.get('uptimesec') == '' else int(output.get('uptimesec'))
        uptime =  uptime_day * 86400 +  uptime_hour * 3600 + uptime_min * 60 + uptime_sec
    st.log("get bfd uptime {} , day {}, hour {}, min {}, sec {}".format(uptime, uptime_day, uptime_hour, uptime_min, uptime_sec))
    return uptime

def double_check_sbfd(dut, sbfd_key, sbfd_check_filed, offload=True, delete=False):
    # show bfd peers | grep 'peer 20.20.20.58 (endpoint 20.20.20.58 color 1 sidlist sl1_ipv4) local-address 20.20.20.58' -A 20
    create_by_hardware = False
    cmd = 'cli -c "no page" -c "show bfd peers" | grep {} -A 20'.format('"'+sbfd_key+'"')
    output = st.show(dut, cmd)
    st.log (output)
    if type(output) != list:
        st.log ("output is not list type")
        return False

    if len(output)>0:
        output = output[0]
    st.log (output)

    if delete:
        if len(output) == 0:
            return True
        if output.get('peer', '') == '':
            return True
        else:
            return False

    uptime1 = get_bfd_uptime_sec(output)
    st.log (sbfd_check_filed)
    for filed, val in sbfd_check_filed.items():
        st.log (filed)
        st.log (val)
        if filed in output :
            if type(output[filed]) == list:
                checkval = output[filed][0]
            else:
                checkval = output[filed]
            if val != checkval:
                st.log("{} 's {} is not match, expect {}".format(sbfd_key, filed, val))
                return False

    st.wait(10)

    output = st.show(dut, cmd)
    if type(output) == list and len(output)>0:
        output = output[0]
    st.log (output)
    uptime2 = get_bfd_uptime_sec(output)
    for filed, val in sbfd_check_filed.items():
        if filed in output :
            if type(output[filed]) == list:
                checkval = output[filed][0]
            else:
                checkval = output[filed]
            if val != checkval:
                st.log("{} 's {} is not match, expect {}".format(sbfd_key, filed, val))
                return False

    if (output['status'] == 'up') and (uptime2 - uptime1 < 10):
        st.log("{} not up continuously".format(sbfd_key))
        return False

    if 'local_id' in output:
        data.current_discr = output['local_id']

    if 'hardware' in output:
        if output['hardware'] == 'hardware':
            create_by_hardware = True

    # show bfd peers counters | grep 'peer 20.20.20.58 (endpoint 20.20.20.58 color 1 sidlist sl1_ipv4) local-address 20.20.20.58' -A 7
    count_cmd = 'cli -c "no page" -c "show bfd peers counters" | grep {} -A 7'.format('"'+sbfd_key+'"')
    output = st.show(dut, count_cmd)
    if type(output) == list and len(output)>0:
        output = output[0]
    st.log (output)

    if offload:
        # check appdb ,check hardware flag
        if create_by_hardware == False:
            st.log("{} not offload".format(sbfd_key))
            return False

    return True

def check_ip_interface_state(dut, interface):
    cmd = "cli -c 'no page' -c 'show ip interface brief'"
    output = st.show(dut, cmd)
    cnt = 0

    for i in range(len(output)):
        state = output[i]['state']
        intf = output[i]['interface'].split('.')
        if state == 'UP' and intf[0] in interface:
            cnt += 1
    
    st.log("cnt:{} len:{}".format(cnt,len(output)))
    if cnt == 8:
        return True
    else:
        return False 

def check_ip_intf_state(dut, interface):
    cmd = "cli -c 'no page' -c 'show ip interface brief'"
    output = st.show(dut, cmd)
    cnt = 0

    for i in range(len(output)):
        state = output[i]['state']
        intf = output[i]['interface'].split('.')
        if state == 'UP' and intf[0] == interface:
            cnt += 1
    
    st.log("cnt:{} len:{}".format(cnt,len(output)))
    if cnt == 256:
        return True
    else:
        return False  


def check_arp_state(dut, interface):
    output = st.show(dut, "show arp")
    cnt = 0
    for i in range(len(output)):
        intf = output[i]['iface'].split('.')
        if intf[0] == interface:
            cnt += 1

    st.log("cnt:{} len:{}".format(cnt,len(output)))

    if cnt == 128:
        return True
    else:
        return False 

def check_ndp_state(dut, interface):
    output = st.show(dut, "show ndp")
    cnt = 0
    for i in range(len(output)):
        intf = output[i]['interface'].split('.')
        if intf[0] == interface:
            cnt += 1

    if cnt == 256:
        return True
    else:
        return False 

def check_asicdb_member(dut):
    check_msg = "Total 768 Entries."
    output = st.show(dut, "cdb asicdb member", skip_tmpl=True)

    if check_msg in output:
        return True
    else:
        return False     

def check_asicdb_member_hash(dut):
    check_msg = "Total 24 Entries."
    output = st.show(dut, "cdb asicdb member", skip_tmpl=True)

    if check_msg in output:
        return True
    else:
        return False  

def check_bgp_state(dut, neighbor_ip):
    output = st.show(dut, 'show bgp neighbors {}'.format(neighbor_ip), type='vtysh')
    bgp_state = output[0]['state'] if output else "NotEstablished"
    return bgp_state == 'Established'

def check_bfd_state(dut, key, check_field):
    return double_check_sbfd(dut, key, check_field, False, False)

def check_bgp_vpn_route_count(dut, neighbor_ip, count, is_ipv6=False):

    if is_ipv6:
        bgp_cmd = "show bgp ipv6 vpn summary neighbor {}".format(neighbor_ip)
    else:
        bgp_cmd = "show bgp ipv4 vpn summary neighbor {}".format(neighbor_ip)

    output = st.show(dut, bgp_cmd, type='vtysh')
    if type(output) == list and len(output)>0:
        output = output[0]
    else:
        return False
    st.log (output)
    pfxrcd = output.get(u'pfxrcd')
    if (pfxrcd == count):
        return True
    return False

def check_bgp_route_count(dut, neighbor_ip,  count, is_ipv6):
    return check_bgp_vpn_route_count(dut, neighbor_ip, count, is_ipv6)

def check_srv6_te_policy_active_count(dut, count):
    
    cmd = "show sr-te tunnel"
    output = st.show(dut, cmd, type='vtysh')
    st.log (output)
    if type(output) == list and len(output)>0:
        output = output[0]
    else:
        return False
    st.log(output)
    activecount = output.get(u'activecount')
    st.log(activecount)
    if (activecount == count):
        return True
    return False


def check_srv6_te_policy_active(dut, count):
    return check_srv6_te_policy_active_count(dut, count)

def show_appdb_table_info(dut, table):
    command = redis.build(dut, redis.APPL_DB, 'keys "{}"'.format(table))
    st.show(dut, command, skip_tmpl=True)
