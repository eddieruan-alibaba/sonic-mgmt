import os

def get_vendor_specific_ixia_config(base_config_name):
    """
    Get vendor-specific IXIA config file name based on environment variable.

    Args:
        base_config_name (str): Base config filename (e.g., "esr_multi_vrf.ixncfg")

    Returns:
        str: Vendor-specific config filename or base filename if vendor file doesn't exist

    Environment Variables:
        SONIC_VENDOR: Vendor name (e.g., 'cisco') to use vendor-specific config files
    """
    vendor = os.getenv('SONIC_VENDOR', 'default').lower()

    if vendor != 'default':
        # Extract base name and extension
        name, ext = os.path.splitext(base_config_name)
        vendor_config = "{}_{}{}".format(name, vendor, ext)
        return vendor_config
    
    return base_config_name

# Dynamic IXIA configuration - can be overridden via environment variables
IXIA_HOST = os.getenv('IXIA_HOST', '192.168.122.168')
# Dynamic IXIA port assignment - can be overridden via environment variable
IXIA_PORT = int(os.getenv('IXIA_PORT', '443'))
# Dynamic IXIA user password - can be overridden via environment variable
IXIA_USER_PASSWORD = os.getenv('IXIA_USER_PASSWORD', 'admin')

ESR_MULTI_VRF_CONFIG = get_vendor_specific_ixia_config("esr_multi_vrf.ixncfg")
ESR_MULTI_VRF_ECMP_CONFIG = get_vendor_specific_ixia_config("esr_multi_vrf_ecmp.ixncfg")
ESR_ECMP_CONFIG = get_vendor_specific_ixia_config("esr_ecmp_04.ixncfg")
ESR_MIRROR_CONFIG = get_vendor_specific_ixia_config("esr_mirror.ixncfg")
ESR_2K_POLICY_CONFIG = get_vendor_specific_ixia_config("esr_te_policy.ixncfg")
ESR_SID_REMARKING_CONFIG = get_vendor_specific_ixia_config("esr_sid_remarking.ixncfg")
ESR_IPV4_IPV6_POLICY_CONFIG = get_vendor_specific_ixia_config("ip_ipv6_te_policy.ixncfg")
ESR_IPV4_IPV6_500K_POLICY_CONFIG = get_vendor_specific_ixia_config("ip_ipv6_500k_te_policy.ixncfg")
ESR_LOCATOR_ENDX_ECMP_128_MEMBER_CONFIG = get_vendor_specific_ixia_config("locator_endx_ecmp_128_member.ixncfg")
ESR_LOCATOR_ENDX_ECMP_V6_HASH_CONFIG = get_vendor_specific_ixia_config("endx_ecmp_hash_v6.ixncfg")

# IXIA_PORT connected to 179
PORT_NAME_1 = "1/1/15"
PORT_NAME_2 = "1/1/16"

# IXIA_PORT connected to 178
PORT_NAME_3 = "1/1/21"
PORT_NAME_4 = "1/1/22"

# Scalable Sources
DEVICE_1_IPV4            ="/api/v1/sessions/1/ixnetwork/topology/1/deviceGroup/1/ethernet/1/ipv4/1" # 1/1/15
DEVICE_2_IPV4            ="/api/v1/sessions/1/ixnetwork/topology/2/deviceGroup/1/ethernet/1/ipv4/1" # 1/1/16

# Scalable Destinations
DEVICE_3_IPV4_PREFIX_POOL="/api/v1/sessions/1/ixnetwork/topology/3/deviceGroup/1/networkGroup/1/ipv4PrefixPools/1" # 1/1/21
DEVICE_4_IPV4_PREFIX_POOL="/api/v1/sessions/1/ixnetwork/topology/4/deviceGroup/1/networkGroup/1/ipv4PrefixPools/1" # 1/1/22


TOPOLOGY_3 = "Topology 3"
DEVICE_GROUP_3 = "Device Group 3"
NETWORK_GROUP_1 = "Network Group 1"
IPV4_PREFIX_POOL_1 = "Basic IPv4 Addresses 1"
BGP_IP_ROUTE_PROPERTY_1 = "BGP IP Route Range 1"

TOPOLOGY_4 = "Topology 4"
DEVICE_GROUP_4 = "Device Group 4"
NETWORK_GROUP_2 = "Network Group 2"
IPV4_PREFIX_POOL_2 = "Basic IPv4 Addresses 2"
BGP_IP_ROUTE_PROPERTY_2 = "BGP IP Route Range 2"

# Traffic items
VRF_TRAFFIC_NAME = "t-g1-1"
SPECIFIC_VRF_TRAFFIC_NAME = "Specific-Vrf_traffic"
ECMP_TRAFFIC_NAME = "traffic_ecmp"
TRAFFIC_MIRROR_V4 = "TI-IPv4"
TRAFFIC_MIRROR_V6 = "TI-IPv6"
TRAFFIC_MIRROR_ULECMP = "ul-ecmp"
TRAFFIC_1K_TE_POLICY = "TE-1k"
TRAFFIC_2K_TE_POLICY = "TE-2K"
TRAFFIC_SID_REMARKING_V4_SUCCESS = "Traffic_SID_remarking_v4_success"
TRAFFIC_SID_REMARKING_V4_FAIL = "Traffic_SID_remarking_v4_fail"
TRAFFIC_SID_REMARKING_V6_SUCCESS = "Traffic_SID_remarking_v6_success"
TRAFFIC_SID_REMARKING_V6_FAIL = "Traffic_SID_remarking_v6_fail"
TRAFFIC_IPV4_TE_POLICY = "TE-IPv4"
TRAFFIC_IPV6_TE_POLICY = "TE-IPv6"

TRAFFIC_ENDX_ECMP_UNUA_V4 = "endx_ecmp_unua_v4"
TRAFFIC_ENDX_ECMP_UA_V4 = "endx_ecmp_ua_v4"
TRAFFIC_ENDX_ECMP_UNUA_V6 = "endx_ecmp_unua_v6"
TRAFFIC_ENDX_ECMP_UA_V6 = "endx_ecmp_ua_v6"
TRAFFIC_NONCOMPRESS_ENDX_ECMP_V4 = "noncompress_endx_ecmp_v4"
TRAFFIC_NONCOMPRESS_ENDX_ECMP_V6 = "noncompress_endx_ecmp_v6"

TRAFFIC_ENDX_ECMP = "Quick Flow Groups"


