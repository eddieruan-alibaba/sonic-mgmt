import time
import logging
import pytest
import os
import ast
import random
import pprint
import requests
import json
import ipaddress
import ptf
import ptf.packet as scapy

from ptf.testutils import simple_tcp_packet
from ptf.mask import Mask
import ptf.packet as packet
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.testutils import send_packet

from tests.common.helpers.assertions import pytest_assert
from collections import defaultdict
from tests.common.utilities import wait_until

from srv6_utils import *
from common_utils import *
from trex_utils import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("any"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health
]

test_vm_names = ["PE1", "PE2", "PE3", "P2", "P3", "P4"]

#
# The port used by ptf to connect with backplane. This number is different from 3 ndoe case.
#
ptf_port_for_backplane = 18
ptf_port_for_p2_to_p1 = 16
ptf_port_for_p2_to_p3 = 36
ptf_port_for_p4_to_p1 = 17
ptf_port_for_p4_to_p3 = 37
ptf_port_for_pe3_to_p2 = 39
ptf_port_for_pe3_to_p4 = 40
ptf_port_for_p1_to_pe1 = 28
ptf_port_for_p1_to_pe2 = 29
ptf_port_for_p3_to_pe1 = 34
ptf_port_for_p3_to_pe2 = 35

# The number of routes published by each CE
num_ce_routes = 10

#
# Routes learnt from pe1 and pe2
#
route_prefix_for_pe1_and_pe2 = "192.100.0"

#
# Routes learnt from pe3
#
route_prefix_for_pe3 = "192.200.0"

#
# This 10 sec sleep is used for make sure software programming is finished
# It has enough buffer zone.
#
sleep_duration = 10

#
# BGP neighbor up waiting time, waiting up to 180 sec
#
bgp_neighbor_up_wait_time = 180

#
# BGP neighbor down waiting time, waiting up to 30 sec
#
bgp_neighbor_down_wait_time = 30

#
# Initialize the testbed
#
def setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost):

    logger.info("step 0 - install trex on PTF")
    trex_install(ptfhost)
    setup_config_for_testbed(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, test_vm_names, "7nodes_te")
    time.sleep(300)
    logger.info("Announce routes from CEs")
    ptfip = ptfhost.mgmt_ip
    nexthop = "10.10.246.254"
    port_num = [5000, 5001, 5002]

    # Publish to PE1
    neighbor = "10.10.246.29"
    # Publish to PE2
    neighbor2 = "10.10.246.30"
    for x in range(1, num_ce_routes+1):
        route = "{}.{}/32".format(route_prefix_for_pe1_and_pe2, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[0])
        announce_route(ptfip, neighbor2, route, nexthop, port_num[1])

    # Publish to PE3
    neighbor = "10.10.246.31"
    for x in range(1, num_ce_routes+1):
        route = "{}.{}/32".format(route_prefix_for_pe3, x)
        announce_route(ptfip, neighbor, route, nexthop, port_num[2])


    nbrhost = nbrhosts["PE3"]['host']
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'bfd' -c 'peer 2064:300::1f   bfd-mode sbfd-echo  bfd-name bfd-b local-address 2064:300::1f encap-type SRv6 encap-data fd00:205:205:fff5:5:: source-ipv6 2064:300::1f'  ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'bfd' -c 'peer 2064:300::1f   bfd-mode sbfd-echo  bfd-name bfd-c local-address 2064:300::1f encap-type SRv6 encap-data fd00:206:206:fff6:6:: source-ipv6 2064:300::1f'  ")


    # sleep make sure all forwarding structures are settled down.
    sleep_duration_after_annournce = 60
    time.sleep(sleep_duration_after_annournce)
    logger.info(
        "Sleep {} seconds to make sure all forwarding structures are "
        "settled down".format(sleep_duration_after_annournce)
    )

#
# Testbed set up
#
@pytest.fixture(scope="module", autouse=True)
def srv6_te_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost):
    setup_config(duthosts, rand_one_dut_hostname, nbrhosts, ptfhost)

def revert_setting_for_test_traffic_multi_policy_check_5(rand_one_dut_hostname,duthosts,nbrhosts):
    dut = duthosts[rand_one_dut_hostname]
    dut.command("sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    dut.command("sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right_to_05 seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P3"]["host"].command("sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P3"]["host"].command("sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right_to_06 seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P4"]["host"].command("sudo vtysh -c 'configure terminal' -c 'no ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhost=nbrhosts["PE3"]["host"]
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 1 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 3 endpoint 2064:200::1e' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name a explicit-srv6 segment-list a weight 1 '")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 '")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 3 endpoint 2064:200::1e' -c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 '")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 3 endpoint 2064:200::1e' -c ' candidate-path preference 1 name d explicit-srv6 segment-list d weight 1 '")
    nbrhosts['P4']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65103' -c 'address-family ipv6 unicast' -c 'redistribute static route-map srv6_r'")
    nbrhosts['P2']['host'].shell("sudo vtysh -c 'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c ' redistribute static route-map srv6_r'")


#
# Test case: check number of Ethnernet interfaces
#
def test_interface_on_each_node(duthosts, rand_one_dut_hostname, nbrhosts):
    for vm_name in test_vm_names:
        nbrhost = nbrhosts[vm_name]['host']
        num, hwsku = find_node_interfaces(nbrhost)
        logger.debug("Get {} interfaces on {}, hwsku {}".format(num, vm_name, hwsku))
        if hwsku == "cisco-8101-p4-32x100-vs":
            pytest_assert(num == 32)

    dut = duthosts[rand_one_dut_hostname]
    num, hwsku = find_node_interfaces(dut)
    logger.debug("Get {} interfaces on {}, hwsku {}".format(num, "dut", hwsku))
    if hwsku == "cisco-8101-p4-32x100-vs":
        pytest_assert(num == 32)
#
# Test Case: Check BGP neighbors
#
def test_check_bgp_neighbors(duthosts, rand_one_dut_hostname, nbrhosts):
    logger.info("Check BGP Neighbors")
    # From PE3
    nbrhost = nbrhosts["PE3"]['host']
    pytest_assert(
        wait_until(
            60, 10, 0, check_bgp_neighbors_func, nbrhost,
            ['2064:100::1d', '2064:200::1e', 'fc06::2', 'fc08::2']
        ),
        "wait for PE3 BGP neighbors up"
    )
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From PE1
    nbrhost = nbrhosts["PE1"]['host']
    check_bgp_neighbors(nbrhost, ['2064:300::1f', '2064:200::1e', 'fc00::71', 'fc02::2'])
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From PE2
    nbrhost = nbrhosts["PE2"]['host']
    check_bgp_neighbors(nbrhost, ['2064:300::1f', '2064:100::1d', 'fc00::75', 'fc03::2'])
    check_bgp_neighbors(nbrhost, ['10.10.246.254'], "Vrf1")
    # From P1
    dut = duthosts[rand_one_dut_hostname]
    check_bgp_neighbors(dut, ['fc00::72', 'fc00::76', 'fc00::7e', 'fc01::85', 'fc00::81'])
    # From P3
    nbrhost = nbrhosts["P3"]['host']
    check_bgp_neighbors(nbrhost, ['fc02::1', 'fc04::1', 'fc00::7d', 'fc03::1', 'fc09::1'])
    # From P2
    nbrhost = nbrhosts["P2"]['host']
    check_bgp_neighbors(nbrhost, ['fc00::82', 'fc09::2', 'fc07::1', 'fc08::1'])
    # From P4
    nbrhost = nbrhosts["P4"]['host']
    check_bgp_neighbors(nbrhost, ['fc01::86', 'fc04::2', 'fc07::2', 'fc06::1'])
#
# Test Case: Check te policy route info
#
def test_check_te_policy_route_info(nbrhosts):
    logger.info("Check route information")
    nbrhost = nbrhosts["PE3"]['host']
    check_vpn_route_info(nbrhost, ['192.100.0.1/32', '192.100.0.2/32'], '01:3','2064:200::1e', '3','Vrf1')
    check_vpn_route_info(nbrhost, ['192.100.0.1/32', '192.100.0.2/32'], '01:1', '2064:100::1d', '1','Vrf1')
    logger.info("Check nexthop group information")
    nexthop_id, pic_id = Get_route_group_id(nbrhost, '192.100.0.1/32', False, 'Vrf1')
    check_route_nexthop_group(nbrhost, nexthop_id, 6)
    check_route_nexthop_group(nbrhost, pic_id, 2)
    #shutdown bgp neighbor
    #nbrhost.command("sudo vtysh -c 'configure terminal' -c 'router bgp 64602' -c 'neighbor 2064:200::1e shutdown'")
    #time.sleep(10)
    #check_bgp_neighbor_func(nbrhost, '2064:200::1e', 'Idle')

    #check_vpn_route_info(nbrhost, ['192.100.0.1/32', '192.100.0.2/32'], '01:1', '2064:100::1d', '1','Vrf1')
    #nexthop_id, pic_id = Get_route_group_id(nbrhost, '192.100.0.1/32', False, 'Vrf1')
    #check_route_nexthop_group(nbrhost, nexthop_id, 3)
    #check_route_nexthop_group(nbrhost, pic_id, 1)
    logger.info("End test_check_te_policy_route_info")
#
# Test Case: Check static route of DT46
#
def test_te_policy_func_dt46(nbrhosts):
    ret = check_static_route_func(nbrhosts["PE1"]['host'], 'fd00:201:201:fff1:1::/80', 'End.DT46')
    pytest_assert(ret == True, "No static route")
    ret = check_vpn_route_is_te(nbrhosts["PE3"]['host'], ['192.100.0.1'],vrf="Vrf1")
    pytest_assert(ret == True, "Check 192.100.0.1 is not te")
    logger.info("End test_te_policy_func_dt46")
#
# Test Case: Check static route of DTX
#
def test_te_policy_func_endx(nbrhosts):
    nbrhosts["PE1"]['host'].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c "
                                    + "'locator lsid1' -c ' prefix fd00:201:201::/48 block-len 32 node-len 16 func-bits 32 ' -c 'opcode ::fff1:3:0:0:0 end-x interface Ethernet2 nexthop 120.2.0.2' ")
    ret = check_static_route_func(nbrhosts["PE1"]['host'], 'fd00:201:201:fff1:3::/80', 'End.X')
    pytest_assert(ret == True, "No static fd00:201:201:fff1:3::/80 route")
    nbrhosts["PE1"]['host'].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c "
                                    + "'locator lsid1' -c ' prefix fd00:201:201::/48 block-len 32 node-len 16 func-bits 32 ' -c 'opcode ::fff1:4:0:0:0 end-x interface Ethernet4 nexthop fc02::2' ")
    ret = check_static_route_func(nbrhosts["PE1"]['host'], 'fd00:201:201:fff1:4::/80', 'End.X')
    pytest_assert(ret == True, "No static fd00:201:201:fff1:4::/80 route")

    nbrhosts["PE1"]['host'].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c "
                                    + "'locator lsid1' -c ' prefix fd00:201:201::/48 block-len 32 node-len 16 func-bits 32 ' -c 'no opcode ::fff1:3:0:0:0' ")
    ret = check_static_route_func(nbrhosts["PE1"]['host'], 'fd00:201:201:fff1:3::/80', 'End.X')
    pytest_assert(ret == False, "No static fd00:201:201:fff1:3::/80 route")
    nbrhosts["PE1"]['host'].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c "
                                    + "'locator lsid1' -c ' prefix fd00:201:201::/48 block-len 32 node-len 16 func-bits 32 ' -c 'no opcode ::fff1:4:0:0:0' ")
    ret = check_static_route_func(nbrhosts["PE1"]['host'], 'fd00:201:201:fff1:4::/80', 'End.X')
    pytest_assert(ret == False, "No static fd00:201:201:fff1:4::/80 route")
    logger.info("End test_te_policy_func_end_endx")
#
# Test Case: Check vpn route recursive with color
#
def test_te_policy_func_color(nbrhosts):
    ret = check_vpn_route_is_te(nbrhosts["PE3"]['host'], ['192.100.0.1'],vrf="Vrf1")
    pytest_assert(ret == True, "Check 192.100.1.0 is not te")
    nbrhosts["PE1"]['host'].command("sudo vtysh -c 'configure terminal' -c 'router bgp 64600 vrf Vrf1' -c 'address-family ipv4 unicast' -c 'no route-map vpn export sr1'")
    nbrhosts["PE2"]['host'].command("sudo vtysh -c 'configure terminal' -c 'router bgp 64601 vrf Vrf1' -c 'address-family ipv4 unicast' -c 'no route-map vpn export sr1'")
    time.sleep(2)
    ret = check_vpn_route_is_te(nbrhosts["PE3"]['host'], ['192.100.0.1'],vrf="Vrf1")
    pytest_assert(ret == False, "Check 192.100.1.0 is te")
    nbrhosts["PE1"]['host'].command("sudo vtysh -c 'configure terminal' -c 'router bgp 64600 vrf Vrf1' -c 'address-family ipv4 unicast' -c 'route-map vpn export sr1'")
    nbrhosts["PE2"]['host'].command("sudo vtysh -c 'configure terminal' -c 'router bgp 64601 vrf Vrf1' -c 'address-family ipv4 unicast' -c 'route-map vpn export sr1'")
    time.sleep(2)
    ret = check_vpn_route_is_te(nbrhosts["PE3"]['host'], ['192.100.0.1'],vrf="Vrf1")
    pytest_assert(ret == True, "Check 192.100.1.0 is not te")
    logger.info("End test_te_policy_func_color")
#
# Test Case: Check traffic of single policy with different preference
#
def test_traffic_single_policy_check_1(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):

    nbrhost=nbrhosts["PE3"]["host"]
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 3 endpoint 2064:200::1e' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 100 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 1 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 2 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "PE3_tx_to_P2": 10000,"PE3_tx_to_P4":0,"P2_tx_to_P1":10000,"P2_tx_to_P3":0, "P1_tx_to_PE1": 5000, "P1_tx_to_PE2": 5000}
    count=0
    done=False
    while done == False and count < 5:
        try:
            check_traffic_single_flow(ptfadapter, ptf_port_for_pe3_to_p2, "fd00:205:205:fff5:5::", seglst = ["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        raise Exception("Traffic test failed")

    nbrhosts['P2']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["down","up"]),
                  "Bfd not established!")
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "PE3_tx_to_P2": 0,"PE3_tx_to_P4":10000, "P4_tx_to_P3": 10000, "P4_tx_to_P1":0,"P3_tx_to_PE1": 5000,"P3_tx_to_PE2": 5000}
    count=0
    done=False
    while done == False and count < 5:
        try:
            check_traffic_single_flow(ptfadapter, ptf_port_for_pe3_to_p4, "fd00:206:206:fff6:6::", seglst = ["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        # rever to previous setting
        nbrhosts['P2']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c 'redistribute static route-map srv6_r'")
        raise Exception("Traffic test failed")

    nbrhosts['P2']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c 'redistribute static route-map srv6_r'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")
    logger.info("End test_traffic_single_policy_check_1")
#
# Test Case: Check traffic of single policy with same preference
#
def test_traffic_single_policy_check_2(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_single_policy_check_2"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)
    nbrhost = nbrhosts["PE3"]['host']
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 3 endpoint 2064:200::1e' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 1 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")

    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P1_tx_to_PE1": 2500, "P1_tx_to_PE2": 2500, "P3_tx_to_PE1": 2500, "P3_tx_to_PE2": 2500,"PE3_tx_to_P2": 5000, "PE3_tx_to_P4": 5000,"P2_tx_to_P1": 5000,"P4_tx_to_P3": 5000 }
    count=0
    done=False
    while done == False and count < 5:
        try:
            check_traffic_double_flow(ptfadapter, "fd00:205:205:fff5:5::", ["fd00:201:201:fff1:1::"], "fd00:206:206:fff6:6::",["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        disable_tcpdump(True)
        raise Exception("Traffic test failed")

    disable_tcpdump(True)
    logger.info("End test_traffic_single_policy_check_2")
#
# Test Case: Check traffic of multi policy with same preference
#
def test_traffic_multi_policy_check_3(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):

    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_multi_policy_check_3"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)
    nbrhost = nbrhosts["PE3"]['host']
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 3 endpoint 2064:200::1e' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 1 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 3 endpoint 2064:200::1e' -c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P1_tx_to_PE1": 2500, "P1_tx_to_PE2": 2500, "P3_tx_to_PE1": 2500, "P3_tx_to_PE2": 2500,"PE3_tx_to_P2": 5000, "PE3_tx_to_P4": 5000,"P2_tx_to_P1": 5000,"P4_tx_to_P3": 5000 }
    done=False
    count=0
    while done == False and count < 5:
        try:
            check_traffic_double_flow(ptfadapter, "fd00:205:205:fff5:5::", ["fd00:201:201:fff1:1::"], "fd00:206:206:fff6:6::",["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        disable_tcpdump(True)
        raise Exception("Traffic test failed")
    disable_tcpdump(True)
    logger.info("End test_traffic_multi_policy_check_3")
#
# Test Case: Check traffic of multi policy with sbfd function
#
def test_traffic_multi_policy_check_4(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    nbrhost = nbrhosts["PE3"]['host']
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 3 endpoint 2064:200::1e' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 1 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1 bfd-name bfd-b'")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 3 endpoint 2064:200::1e' -c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1 bfd-name bfd-c'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P1_tx_to_PE1": 2500, "P1_tx_to_PE2": 2500, "P3_tx_to_PE1": 2500, "P3_tx_to_PE2": 2500,"PE3_tx_to_P2": 5000, "PE3_tx_to_P4": 5000,"P2_tx_to_P1": 5000,"P4_tx_to_P3": 5000 }
    done=False
    count=0
    while done == False and count < 5:
        try:
            check_traffic_double_flow(ptfadapter, "fd00:205:205:fff5:5::", ["fd00:201:201:fff1:1::"], "fd00:206:206:fff6:6::",["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        raise Exception("Traffic test failed")

    nbrhosts['P2']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["down","up"]),
                  "Bfd not established!")
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P1_tx_to_PE1": 0, "P1_tx_to_PE2": 0, "P3_tx_to_PE1": 5000, "P3_tx_to_PE2": 5000,"PE3_tx_to_P2": 0, "PE3_tx_to_P4": 10000}
    done=False
    count=0
    while done == False and count < 5:
        try:
            check_traffic_single_flow(ptfadapter, ptf_port_for_pe3_to_p4, "fd00:206:206:fff6:6::", seglst = ["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        #revert to original setting
        nbrhosts['P2']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c ' redistribute static route-map srv6_r'")
        raise Exception("Traffic test failed")
    nbrhosts['P2']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c ' redistribute static route-map srv6_r'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b"], ["up"]),
                  "Bfd not established!")
    logger.info("End test_traffic_multi_policy_check_4")
#
# Test Case: Check traffic of SRv6-TE and SRv6-BE hybrid mode
#
def test_traffic_multi_policy_check_5(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    # Enable tcpdump for debugging purpose, file_loc is host file location
    intf_list = ["VM0102-t1", "VM0102-t3"]
    file_loc = "~/sonic-mgmt/tests/logs/"
    prefix = "test_traffic_multi_policy_check_5"
    enable_tcpdump(intf_list, file_loc, prefix, True, True)
    nbrhost=nbrhosts["PE3"]["host"]
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 3 endpoint 2064:200::1e' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 1 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1  bfd-name bfd-b'")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1  bfd-name bfd-c'")
    dut = duthosts[rand_one_dut_hostname]
    dut.command("sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    dut.command("sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right_to_05 seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P3"]["host"].command("sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P3"]["host"].command("sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right_to_06 seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    nbrhosts["P4"]["host"].command("sudo vtysh -c 'configure terminal' -c 'ipv6 prefix-list srv6_right seq 50 permit fd00:201:201:fff1:1::/80 le 128' ")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")
    done=False
    count=0
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P1_tx_to_PE1": 2500, "P1_tx_to_PE2": 2500, "P3_tx_to_PE1": 2500, "P3_tx_to_PE2": 2500,"PE3_tx_to_P2": 5000, "PE3_tx_to_P4": 5000,"P2_tx_to_P1": 5000,"P4_tx_to_P3": 5000 }
    while done == False and count < 5:
        try:
            check_traffic_double_flow(ptfadapter, "fd00:205:205:fff5:5::", ["fd00:201:201:fff1:1::"], "fd00:206:206:fff6:6::",["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        revert_setting_for_test_traffic_multi_policy_check_5(rand_one_dut_hostname,duthosts, nbrhosts)
        raise Exception("Traffic test failed")

    nbrhosts['P4']['host'].shell("sudo vtysh -c  'configure terminal' -c 'router bgp 65103' -c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'")
    nbrhosts['P2']['host'].shell("sudo vtysh -c 'configure terminal' -c 'router bgp 65102' -c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["down","down"]),
                  "Bfd not established!")
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P2_tx_to_P1": 2500, "P2_tx_to_P3": 2500, "P4_tx_to_P1": 2500, "P4_tx_to_P3": 2500,"PE3_tx_to_P2": 5000, "PE3_tx_to_P4": 5000}
    done=False
    count=0
    while done == False and count < 5:
        try:
            check_traffic_be_flow(ptfadapter, "fd00:201:201:fff1:1::", traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        revert_setting_for_test_traffic_multi_policy_check_5(rand_one_dut_hostname,duthosts, nbrhosts)
        raise Exception("Traffic test failed")

    revert_setting_for_test_traffic_multi_policy_check_5(rand_one_dut_hostname,duthosts, nbrhosts)
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")
    disable_tcpdump(True)
    logger.info("End test_traffic_multi_policy_check_5")
#
# Test Case: Check traffic of multi vpn sid
#
def test_traffic_multi_policy_check_6(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, ptfadapter):
    # Enable tcpdump for debugging purpose, file_loc is host file location
    nbrhost=nbrhosts["PE3"]["host"]
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 3 endpoint 2064:200::1e' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'no policy color 1 endpoint 2064:100::1d' ")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 1 endpoint 2064:100::1d' -c ' candidate-path preference 1 name b explicit-srv6 segment-list b weight 1  bfd-name bfd-b'")
    nbrhost.command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 3 endpoint 2064:200::1e' -c ' candidate-path preference 1 name c explicit-srv6 segment-list c weight 1  bfd-name bfd-c'")
    nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'no locator lsid1' ")
    nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'locator lsid1 ' -c 'prefix fd00:202:202::/48 block-len 32  node-len 16 func-bits 32'  -c 'opcode ::fff2:2:0:0:0  end-dt46 vrf Vrf1' ")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","up"]),
                  "Bfd not established!")

    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P1_tx_to_PE1": 5000, "P1_tx_to_PE2": 0, "P3_tx_to_PE1": 0, "P3_tx_to_PE2": 5000,"PE3_tx_to_P2": 5000, "PE3_tx_to_P4": 5000}
    done=False
    count=0
    while done == False and count < 5:
        try:
            check_traffic_double_flow(ptfadapter, "fd00:205:205:fff5:5::", ["fd00:201:201:fff1:1::"], "fd00:206:206:fff6:6::",["fd00:202:202:fff2:2::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'no locator lsid1' ")
        nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'locator lsid1 ' -c 'prefix fd00:201:201::/48 block-len 32  node-len 16 func-bits 32'  -c 'opcode ::fff1:1:0:0:0  end-dt46 vrf Vrf1' ")
        raise Exception("Traffic test failed")

    nbrhosts['P4']['host'].shell("sudo vtysh -c 'configure terminal' -c 'router bgp 65103' -c 'address-family ipv6 unicast' -c 'no redistribute static route-map srv6_r'")
    pytest_assert(wait_until(100, 1, 0, check_bfd_status, nbrhosts['PE3']['host'], ["b","c"], ["up","down"]),
                  "Bfd not established!")
    expected_list = {"ptf_tot_rx": 10000, "ptf_tot_tx": 10000, "P1_tx_to_PE1": 10000, "P1_tx_to_PE2": 0, "P3_tx_to_PE1": 0, "P3_tx_to_PE2": 0,"PE3_tx_to_P2": 10000, "PE3_tx_to_P4": 0}
    done=False
    count=0
    while done == False and count < 5:
        try:
            check_traffic_single_flow(ptfadapter, ptf_port_for_pe3_to_p2, "fd00:205:205:fff5:5::", seglst = ["fd00:201:201:fff1:1::"],traffic_check=expected_list)
        except BaseException as e:
            count = count + 1
            logger.info("{}, retry traffic test latter".format(e))
            time.sleep(60)
        else:
            done=True
    if not done:
        nbrhosts['P4']['host'].shell("sudo vtysh -c 'configure terminal' -c 'router bgp 65103' -c 'address-family ipv6 unicast' -c 'redistribute static route-map srv6_r'")
        nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'no locator lsid1' ")
        nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'locator lsid1 ' -c 'prefix fd00:201:201::/48 block-len 32  node-len 16 func-bits 32'  -c 'opcode ::fff1:1:0:0:0  end-dt46 vrf Vrf1' ")
        raise Exception("Traffic test failed")

    nbrhosts['P4']['host'].shell("sudo vtysh -c 'configure terminal' -c 'router bgp 65103' -c 'address-family ipv6 unicast' -c 'redistribute static route-map srv6_r'")
    nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'no locator lsid1' ")
    nbrhosts["PE2"]["host"].command("sudo vtysh -c 'configure terminal' -c 'segment-routing' -c 'srv6' -c 'locators' -c 'locator lsid1 ' -c 'prefix fd00:201:201::/48 block-len 32  node-len 16 func-bits 32'  -c 'opcode ::fff1:1:0:0:0  end-dt46 vrf Vrf1' ")
    logger.info("End test_traffic_multi_policy_check_6")



