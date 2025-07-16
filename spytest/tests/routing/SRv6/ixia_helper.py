import os
import gc
import re

from spytest import st, tgapi, SpyTestDict
from ixia_vars import *
from ixia_lib import IxiaController
from ixnetwork_restpy.assistants.batch.batchadd import BatchAdd


ixia_controller = None

def get_dynamic_chassis_info():
    """
    Get chassis IP and available ports from the TG runtime configuration
    instead of using hardcoded values.
    """
    try:
        # Get the TG chassis object from spytest
        tg = tgapi.get_chassis()
        if not tg:
            st.log("No TG chassis available, falling back to environment variables")
            return IXIA_HOST, []
        
        # Get chassis IP from TG object
        chassis_ip = tg.tg_ip if hasattr(tg, 'tg_ip') else IXIA_HOST
        
        # Get available ports from tg_port_handle
        available_ports = []
        if hasattr(tg, 'tg_port_handle') and tg.tg_port_handle:
            available_ports = list(tg.tg_port_handle.keys())
            st.log("Found {} available ports from TG: {}".format(len(available_ports), available_ports))
        else:
            st.log("No port handles available from TG, using empty port list")
        
        st.log("Using dynamic chassis IP: {} with ports: {}".format(chassis_ip, available_ports))
        return chassis_ip, available_ports
        
    except Exception as e:
        st.log("Failed to get dynamic chassis info: {}, falling back to environment variables".format(str(e)))
        return IXIA_HOST, []

def ixia_controller_init():
    global ixia_controller
    st.log("Ixia controller init start")
    try:
        ixia_controller = IxiaController(IXIA_HOST, IXIA_PORT)
        st.log("Ixia controller connection established")

        # Get chassis IP and ports dynamically from TG runtime configuration
        chassis_ip, available_ports = get_dynamic_chassis_info()

        if available_ports:
            st.log("Configuring port ownership for {} ports".format(len(available_ports)))
            ixia_controller.ensure_port_ownership(chassis_ip, available_ports)
        else:
            st.log("No available ports found, skipping port ownership configuration")

        # Skip port ownership management for now to avoid API compatibility issues
        # This can be re-enabled once the specific API version is determined
        st.log("Skipping port ownership management due to API compatibility")

        st.log("Ixia controller init completed")
        return True
    except Exception as e:
        st.error("Ixia controller init failed: {}".format(str(e)))

        # Provide helpful error messages
        if "Unable to connect" in str(e):
            st.log("Connection issue - check network connectivity to {}".format(IXIA_HOST))
        elif "Port is owned by others" in str(e):
            st.log("Port ownership issue - another user may be using the chassis")
            st.log("Try running the troubleshooting script: ./ixia_troubleshoot.sh")

        # Don't attempt cleanup on init failure to avoid more errors
        raise


def ixia_controller_deinit():
    global ixia_controller
    st.log("Ixia controller deinit start")
    if ixia_controller:
        try:
            # Basic cleanup without complex port ownership management
            st.log("Performing basic Ixia cleanup")
            # Just set to None for now, let the session assistant handle cleanup
        except Exception as e:
            st.error("Failed during cleanup: {}".format(str(e)))

    ixia_controller = None
    gc.collect()
    st.log("Ixia controller deinit completed")

def ixia_add_traffic_item_for_specific_vrf():
    traffic_item = ixia_controller.add_traffic_item(SPECIFIC_VRF_TRAFFIC_NAME)
    st.log("Add IXIA traffic item {} completed.".format(SPECIFIC_VRF_TRAFFIC_NAME))

    # generate 5 endpoint for endpoint
    endpoint_range = [
        #
        [ DEVICE_1_IPV4, "1", DEVICE_3_IPV4_PREFIX_POOL, "10" ],
        [ DEVICE_1_IPV4, "1", DEVICE_3_IPV4_PREFIX_POOL, "30" ],
        [ DEVICE_1_IPV4, "1", DEVICE_3_IPV4_PREFIX_POOL, "50" ],
        [ DEVICE_1_IPV4, "1", DEVICE_4_IPV4_PREFIX_POOL, "70" ],
        [ DEVICE_1_IPV4, "1", DEVICE_4_IPV4_PREFIX_POOL, "90" ],
    ]

    for item in endpoint_range:
        scalable_sources = [
            {"arg1": item[0], "arg2": "1", "arg3": "1", "arg4": item[1], "arg5": "1"},
        ]
        scalable_destionations = [
            {"arg1": item[2], "arg2": "1", "arg3": "1", "arg4": item[3], "arg5": "1"},
        ]
        endpoint_set = traffic_item.EndpointSet.add(
            ScalableSources=scalable_sources, ScalableDestinations=scalable_destionations
        )

    st.log("Add IXIA traffic item {} endpoints completed.".format(SPECIFIC_VRF_TRAFFIC_NAME))
    with BatchAdd(ixia_controller.ixnetwork):
        config_element = traffic_item.ConfigElement.add()
        config_element.FrameRate.Type = "percentLineRate"
        config_element.FrameRate.Rate = 50
        config_element.TransmissionControl.Type = "fixedFrameCount"
        config_element.TransmissionControl.FrameCount = 10000
        config_element.FrameSize.FixedSize = 64

    st.log("Add IXIA traffic item {} config element completed.".format(SPECIFIC_VRF_TRAFFIC_NAME))
    return True


def ixia_check_port_rx_frame(port_name, rx_count):
    port_stats = ixia_controller.get_port_statistics(port_name)
    if port_stats is None:
        return False

    tmp_rx_count = port_stats['Valid Frames Rx.']
    st.log("Get port Rx {} Frames count {},  expect count {}".format(port_name, tmp_rx_count, rx_count))
    if tmp_rx_count == rx_count:
        return True
    return False


def ixia_check_traffic_item_rx_frame(traffic_item_name, key, rx_count, exact_match):
    st.log("check traffic item rx frame begin")
    traffic_item_stats = ixia_controller.get_traffic_item_statistics(traffic_item_name)
    if traffic_item_stats is None:
        return False
    st.log("Get traffic item statistics {}".format(traffic_item_name))
    st.log("\n")
    st.log(traffic_item_stats)

    tmp_rx_count = traffic_item_stats[key]
    st.log("Get traffic item {} Rx Frames count {},  expect count {}".format(traffic_item_name, tmp_rx_count, rx_count))

    match = re.match("\d+", tmp_rx_count)
    if match:
        tmp_rx_count_int = int(match.group())
    else:
        raise ValueError("Invalid integer format")

    if exact_match is True:
        if int(tmp_rx_count_int) == int(rx_count):
            return True
    else:
        deviation = abs(tmp_rx_count_int - rx_count)
        percent = (float(deviation)/rx_count)*100
        if percent < 10:
            return True
    return False

def ixia_get_traffic_stat(traffic_item_name):
    st.log("get traffic stat begin")
    traffic_item_stats = ixia_controller.get_traffic_item_statistics(traffic_item_name)
    if traffic_item_stats is None:
        return None
    st.log("Get traffic item statistics {}".format(traffic_item_name))
    st.log("\n")
    st.log(traffic_item_stats)
    return traffic_item_stats

def ixia_load_config(config_file_name):
    try:
        ixia_controller.new_config()
        st.wait(20)
        st.log("load config {} begin".format(config_file_name))
        ixia_controller.load_config(config_file_name)
        # wait 30 sec for config load
        st.wait(30)
        st.log("load config {} completed".format(config_file_name))
        return True
    except Exception as e:
        st.error("Failed to load config {}: {}".format(config_file_name, str(e)))
        if "Port is owned by others" in str(e) or "No ports assigned" in str(e):
            st.log("Port ownership issue detected during config load")
            st.log("Run troubleshooting: ./ixia_troubleshoot.sh")
            st.log("Or try: python3 ixia_port_manager.py --chassis {} --cleanup".format(IXIA_HOST))
            return False
        else:
            st.error("Non-port related config load error: {}".format(str(e)))
            return False


def ixia_start_all_protocols():
    st.log("IXIA start all protocols begin")
    try:
        ixia_controller.start_all_protocols()
        # wait 20 sec for vrf bgp established
        st.wait(20)
        st.log("IXIA start all protocols completed.")
        return True
    except Exception as e:
        st.error("Failed to start all protocols: {}".format(str(e)))
        if "Port is owned by others" in str(e) or "No ports assigned" in str(e):
            st.log("Attempting to resolve port ownership issues...")
            try:
                # Try to force cleanup and retry
                ixia_controller.force_cleanup_ports()
                st.wait(5)  # Wait for cleanup

                # Reload the configuration
                st.log("Retrying protocol start after cleanup...")
                ixia_controller.start_all_protocols()
                st.wait(20)
                st.log("IXIA start all protocols completed after retry.")
                return True
            except Exception as retry_error:
                st.error("Protocol start failed even after cleanup: {}".format(str(retry_error)))
                st.log("Please run the troubleshooting script: ./ixia_troubleshoot.sh")
                return False
        else:
            st.error("Non-port ownership related error in start_all_protocols")
            return False




def ixia_stop_all_protocols():
    st.log("IXIA stop all protocols begin")
    ixia_controller.stop_all_protocols()
    # wait 20 sec for vrf bgp drop
    st.wait(20)
    st.log("IXIA stop all protocols completed.")
    return True


def ixia_check_traffic(traffic_item_name, key="Rx Frames", value="0", exact_match=True):
    """
    Check traffic with robust error handling and recovery mechanisms.

    Args:
        traffic_item_name: Name of the traffic item to check
        key: Statistic key to check (default: "Rx Frames")
        value: Expected value for comparison
        exact_match: Whether to do exact match or allow 10% deviation

    Returns:
        bool: True if traffic check passes, False otherwise
    """
    try:
        st.wait(10)
        st.log("Checking traffic item: {}".format(traffic_item_name))

        # Validate that traffic item exists before proceeding
        try:
            traffic_item = ixia_controller.get_traffic_item(traffic_item_name)
            if not traffic_item:
                st.error("Traffic item {} not found".format(traffic_item_name))
                return False
        except Exception as e:
            st.error("Failed to get traffic item {}: {}".format(traffic_item_name, str(e)))
            return False

        # Apply traffic configuration with retry logic
        st.log("Applying traffic configuration for {}".format(traffic_item_name))
        max_retries = 3
        apply_success = False
        for attempt in range(max_retries):
            try:
                ixia_controller.traffic_apply()
                apply_success = True
                st.log("Traffic apply successful on attempt {}".format(attempt + 1))
                break
            except Exception as e:
                st.log("Traffic apply attempt {} failed: {}".format(attempt + 1, str(e)))
                if attempt < max_retries - 1:
                    st.log("Retrying traffic apply in 5 seconds...")
                    st.wait(5)

                    # Try to regenerate traffic configuration
                    try:
                        st.log("Regenerating traffic configuration...")
                        ixia_controller.generate_traffic()
                        st.wait(5)
                    except Exception as gen_e:
                        st.log("Traffic regeneration failed: {}".format(str(gen_e)))
                else:
                    st.error("Traffic apply failed after {} attempts: {}".format(max_retries, str(e)))
                    return False

        if not apply_success:
            st.error("Failed to apply traffic configuration for {}".format(traffic_item_name))
            return False

        st.wait(10)

        # Start traffic with error handling
        st.log("Starting traffic item {}".format(traffic_item_name))
        try:
            ret = ixia_controller.start_stateless_traffic(traffic_item_name)
            if not ret:
                st.error("Start traffic item {} failed - returned False".format(traffic_item_name))
                return False
        except Exception as e:
            st.error("Exception during start traffic {}: {}".format(traffic_item_name, str(e)))
            return False

        # Wait for traffic completion
        st.log("Waiting for traffic completion: {}".format(traffic_item_name))
        st.wait(20)

        # Stop traffic with error handling
        try:
            ret = ixia_controller.stop_stateless_traffic(traffic_item_name)
            if not ret:
                st.error("Stop traffic item {} failed - returned False".format(traffic_item_name))
                # Don't return False here, we still want to check statistics
                st.log("Continuing with statistics check despite stop failure")
        except Exception as e:
            st.error("Exception during stop traffic {}: {}".format(traffic_item_name, str(e)))
            st.log("Continuing with statistics check despite stop exception")

        # Check traffic statistics
        if key == "Rx Frames" or key == "Rx Frame Rate":
            try:
                return ixia_check_traffic_item_rx_frame(traffic_item_name, key, value, exact_match)
            except Exception as e:
                st.error("Exception during statistics check for {}: {}".format(traffic_item_name, str(e)))
                return False
        else:
            st.error("Unsupported check key for traffic: {}".format(key))
            return False

    except Exception as e:
        st.error("Unexpected exception in ixia_check_traffic for {}: {}".format(traffic_item_name, str(e)))

        # Provide troubleshooting hints based on error type
        error_str = str(e).lower()
        if "badrequest" in error_str or "bad request" in error_str:
            st.log("BadRequest error suggests invalid traffic configuration or API state")
            st.log("Try regenerating traffic configuration or restarting protocols")
        elif "port" in error_str and ("owned" in error_str or "assign" in error_str):
            st.log("Port ownership issue detected")
            st.log("Run: python3 ixia_port_manager.py --chassis {} --cleanup".format(IXIA_HOST))
        elif "connect" in error_str:
            st.log("Connection issue - check network connectivity to Ixia chassis")

        return False


def ixia_config_bgp_flapping(topology_name, device_group_name, ethernet_name,
                 ipv4_name, bgp_peer_name, enable):

    item = ixia_controller.get_ipv4_bgp_peer(topology_name, device_group_name, ethernet_name,
                 ipv4_name, bgp_peer_name)
    if not item:
        print("Failed to get ipv4 bgp peer")

    if enable:
        res = ixia_controller.enable_ipv4_bgp_peer_flapping(item, 10, 10)
    else:
        res = ixia_controller.disable_ipv4_bgp_peer_flapping(item)
    if not res:
        st.log("Set bgp peer flapping failed")

    topology = ixia_controller.ixnetwork.Globals.find().Topology.find()
    topology.ApplyOnTheFly()

def ixia_config_bgp_ipv6_flapping(topology_name, device_group_name, ethernet_name,
                 ipv6_name, bgp_peer_name, enable):

    item = ixia_controller.get_ipv6_bgp_peer(topology_name, device_group_name, ethernet_name,
                 ipv6_name, bgp_peer_name)
    if not item:
        print("Failed to get ipv6 bgp peer")

    if enable:
        res = ixia_controller.enable_ipv6_bgp_peer_flapping(item, 10, 10)
    else:
        res = ixia_controller.disable_ipv6_bgp_peer_flapping(item)
    if not res:
        st.log("Set bgp peer flapping failed")

    topology = ixia_controller.ixnetwork.Globals.find().Topology.find()
    topology.ApplyOnTheFly()

def ixia_start_traffic(traffic_item_name):
    """
    Start traffic with robust error handling and retry logic.

    Args:
        traffic_item_name: Name of the traffic item to start

    Returns:
        bool: True if traffic started successfully, False otherwise
    """
    try:
        st.wait(10)
        st.log("Starting traffic item: {}".format(traffic_item_name))

        # Validate that traffic item exists
        try:
            traffic_item = ixia_controller.get_traffic_item(traffic_item_name)
            if not traffic_item:
                st.error("Traffic item {} not found".format(traffic_item_name))
                return False
        except Exception as e:
            st.error("Failed to get traffic item {}: {}".format(traffic_item_name, str(e)))
            return False

        # Apply traffic with retry logic
        st.log("Applying traffic configuration for {}".format(traffic_item_name))
        max_retries = 3
        apply_success = False

        for attempt in range(max_retries):
            try:
                ixia_controller.traffic_apply()
                apply_success = True
                st.log("Traffic apply successful on attempt {}".format(attempt + 1))
                break
            except Exception as e:
                st.log("Traffic apply attempt {} failed: {}".format(attempt + 1, str(e)))
                if attempt < max_retries - 1:
                    st.log("Retrying traffic apply in 5 seconds...")
                    st.wait(5)

                    # Try to regenerate traffic configuration
                    try:
                        st.log("Regenerating traffic configuration...")
                        ixia_controller.generate_traffic()
                        st.wait(5)
                    except Exception as gen_e:
                        st.log("Traffic regeneration failed: {}".format(str(gen_e)))
                else:
                    st.error("Traffic apply failed after {} attempts: {}".format(max_retries, str(e)))
                    return False

        if not apply_success:
            st.error("Failed to apply traffic configuration for {}".format(traffic_item_name))
            return False

        st.wait(10)

        # Start traffic with error handling
        st.log("Starting stateless traffic: {}".format(traffic_item_name))
        try:
            ret = ixia_controller.start_stateless_traffic(traffic_item_name)
            if not ret:
                st.error("Start traffic item {} failed - returned False".format(traffic_item_name))
                return False
        except Exception as e:
            st.error("Exception during start traffic {}: {}".format(traffic_item_name, str(e)))
            return False

        st.wait(20)
        st.log("Traffic item {} started successfully".format(traffic_item_name))
        return True

    except Exception as e:
        st.error("Unexpected exception in ixia_start_traffic for {}: {}".format(traffic_item_name, str(e)))
        # Provide troubleshooting hints
        error_str = str(e).lower()
        if "badrequest" in error_str or "bad request" in error_str:
            st.log("BadRequest error suggests invalid traffic configuration or API state")
            st.log("Try regenerating traffic configuration or restarting protocols")
        elif "port" in error_str and ("owned" in error_str or "assign" in error_str):
            st.log("Port ownership issue detected")
            st.log("Run: python3 ixia_port_manager.py --chassis {} --cleanup".format(IXIA_HOST))
        return False

def ixia_stop_traffic(traffic_item_name):
    ret = ixia_controller.stop_stateless_traffic(traffic_item_name)
    if not ret:
        st.error("stop traffic item {} failed".format(traffic_item_name))
        return False
    st.wait(10)
    return True


def ixia_start_all_traffic():
    """
    Start all traffic items with robust error handling.

    Returns:
        bool: True if all traffic started successfully, False otherwise
    """
    try:
        st.log("Starting all traffic items with error handling")

        # Generate traffic with error handling
        st.log("Generating traffic configuration")
        try:
            ixia_controller.generate_traffic()
            st.wait(10)
        except Exception as e:
            st.error("Failed to generate traffic: {}".format(str(e)))
            return False

        # Apply traffic with retry logic
        st.log("Applying traffic configuration")
        max_retries = 3
        apply_success = False

        for attempt in range(max_retries):
            try:
                ixia_controller.traffic_apply()
                apply_success = True
                st.log("Traffic apply successful on attempt {}".format(attempt + 1))
                break
            except Exception as e:
                st.log("Traffic apply attempt {} failed: {}".format(attempt + 1, str(e)))
                if attempt < max_retries - 1:
                    st.log("Retrying traffic apply in 5 seconds...")
                    st.wait(5)
                    # Try to regenerate traffic configuration
                    try:
                        st.log("Regenerating traffic configuration...")
                        ixia_controller.generate_traffic()
                        st.wait(5)
                    except Exception as gen_e:
                        st.log("Traffic regeneration failed: {}".format(str(gen_e)))
                else:
                    st.error("Traffic apply failed after {} attempts: {}".format(max_retries, str(e)))
                    return False

        if not apply_success:
            st.error("Failed to apply traffic configuration")
            return False

        st.wait(10)

        # Start all traffic with error handling
        st.log("Starting all stateless traffic")
        try:
            ret = ixia_controller.start_all_stateless_traffic()
            if not ret:
                st.error("Start all traffic failed - returned False")
                return False
        except Exception as e:
            st.error("Exception during start all traffic: {}".format(str(e)))
            return False

        st.wait(10)
        st.log("All traffic items started successfully")
        return True
    except Exception as e:
        st.error("Unexpected exception in ixia_start_all_traffic: {}".format(str(e)))

        # Provide troubleshooting hints
        error_str = str(e).lower()
        if "badrequest" in error_str or "bad request" in error_str:
            st.log("BadRequest error suggests invalid traffic configuration or API state")
            st.log("Try restarting protocols or reloading configuration")
        elif "port" in error_str and ("owned" in error_str or "assign" in error_str):
            st.log("Port ownership issue detected")
            st.log("Run: python3 ixia_port_manager.py --chassis {} --cleanup".format(IXIA_HOST))
        return False    


def ixia_stop_all_traffic():
    ret = ixia_controller.stop_all_stateless_traffic()
    if not ret:
        st.error("Stop all traffic item failed")
        return False
    st.wait(10)
    return True


def ixia_start_logging_port_view():
    ixia_controller.enable_csv_logging(caption="Port Statistics")
    st.wait(10)
    return True


def ixia_stop_logging_port_view():
    ixia_controller.disable_csv_logging(caption="Port Statistics")
    st.wait(10)
    return True


def ixia_get_port_view_data(local_file):
    csv_file_name = "Port Statistics.csv"
    st.log("Remote dir path: {}".format(ixia_controller.get_csv_file_path(caption="Port Statistics")))
    remote_file_path = "{}/{}".format(ixia_controller.get_csv_file_path(caption="Port Statistics"), csv_file_name)
    ixia_controller.download_file(remote_file_path, local_file)
    return True

def ixia_disable_traffic(traffic_item_name):
    traffic_item = ixia_controller.get_traffic_item(traffic_item_name)
    if traffic_item.Enabled:
        traffic_item.Enabled = False
def ixia_enable_traffic(traffic_item_name):
    traffic_item = ixia_controller.get_traffic_item(traffic_item_name)
    if not traffic_item.Enabled:
        traffic_item.Enabled = True

def get_chassis_ip():
    """Get chassis IP dynamically from TG configuration."""
    chassis_ip, _ = get_dynamic_chassis_info()
    return chassis_ip

def get_available_ports():
    """Get available ports dynamically from TG configuration."""
    _, available_ports = get_dynamic_chassis_info()
    return available_ports

def get_tg_port_handles():
    """Get TG port handles dictionary for advanced port management."""
    try:
        tg = tgapi.get_chassis()
        if tg and hasattr(tg, 'tg_port_handle'):
            return tg.tg_port_handle
        return {}
    except Exception as e:
        st.log("Failed to get TG port handles: {}".format(str(e)))
        return {}
