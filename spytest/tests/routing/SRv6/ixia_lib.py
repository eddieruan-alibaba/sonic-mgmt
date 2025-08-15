from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy import Files
from ixnetwork_restpy.assistants.batch.batchadd import BatchAdd
import os
import json
import time


class IxiaController():

    def __init__(self, host, port, username=None, password=None):
        # Set default credentials if not provided
        if username is None:
            username = os.getenv('IXIA_USERNAME', 'admin')
        if password is None:
            password = os.getenv('IXIA_PASSWORD', 'admin')
            
        print(f"Attempting to connect to IXIA chassis at {host}:{port} with username: {username}")
        
        # Try different authentication methods
        auth_methods = [
            # Method 1: With username and password
            {
                'IpAddress': host,
                'RestPort': port,
                'UserName': username,
                'Password': password,
                'LogLevel': SessionAssistant.LOGLEVEL_INFO,
                'ClearConfig': True,
            },
            # Method 2: Without explicit credentials (for older IXIA versions or default auth)
            {
                'IpAddress': host,
                'RestPort': port,
                'LogLevel': SessionAssistant.LOGLEVEL_INFO,
                'ClearConfig': True,
            }
        ]
        
        last_error = None
        for i, auth_params in enumerate(auth_methods, 1):
            try:
                print(f"Trying authentication method {i}...")
                self.session_assistant = SessionAssistant(**auth_params)
                print(f"Successfully connected using method {i}")
                break
            except Exception as e:
                print(f"Authentication method {i} failed: {e}")
                last_error = e
                if i < len(auth_methods):
                    print(f"Trying next method...")
                    time.sleep(2)  # Brief pause between attempts
        else:
            # All methods failed
            error_msg = f"All authentication methods failed. Last error: {last_error}"
            print(error_msg)
            raise Exception(error_msg)

        self.ixnetwork = self.session_assistant.Ixnetwork
        self.owned_ports = []  # Track owned ports for cleanup
        print("Ixia controller initialized successfully")

    def new_config(self):
        try:
            self.ixnetwork.NewConfig()
        except Exception as e:
            print("Warning: NewConfig failed: {}".format(str(e)))
            # Force cleanup and retry
            self.force_cleanup_ports()
            self.ixnetwork.NewConfig()

    def load_config(self, file_name):
        file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), file_name
        )

        self.ixnetwork.LoadConfig(Files(file_path, local_file=True))

    def force_cleanup_ports(self):
        """Force cleanup of all ports to resolve ownership conflicts"""
        try:
            print("Attempting to force cleanup ports...")
            # Get all chassis
            chassis_list = self.ixnetwork.AvailableHardware.Chassis.find()

            for chassis in chassis_list:
                cards = chassis.Card.find()
                for card in cards:
                    ports = card.Port.find()
                    for port in ports:
                        try:
                            # Force release port ownership
                            if hasattr(port, 'ReleasePort'):
                                port.ReleasePort()
                            # Clear port ownership
                            if hasattr(port, 'ClearOwnership'):
                                port.ClearOwnership()
                        except Exception as port_error:
                            print("Failed to cleanup port {}: {}".format(port, str(port_error)))

            # Clear all vports
            vports = self.ixnetwork.Vport.find()
            for vport in vports:
                try:
                    vport.remove()
                except Exception as vport_error:
                    print("Failed to remove vport {}: {}".format(vport, str(vport_error)))

        except Exception as e:
            print("Force cleanup failed: {}".format(str(e)))

    def ensure_port_ownership(self, chassis_ip, port_list):
        """
        Ensure ports are properly owned before configuration.

        This method now supports both port location formats:
        - Legacy format: "1/1", "2/3", etc.
        - Alternative format: "1.1", "2.3", etc.

        Args:
            chassis_ip (str): IP address of the Ixia chassis
            port_list (list): List of port locations in either format

        Returns:
            None (logs success/failure for each port)
        """
        try:
            print("Ensuring ownership of ports {} on chassis {}".format(port_list, chassis_ip))

            # Check if chassis already exists
            chassis_list = self.ixnetwork.AvailableHardware.Chassis.find(Hostname=chassis_ip)
            if not chassis_list:
                # Add chassis if not present
                chassis = self.ixnetwork.AvailableHardware.Chassis.add(Hostname=chassis_ip)
            else:
                chassis = chassis_list[0]

            # Connect to chassis using the correct method
            try:
                if hasattr(chassis, 'Connect'):
                    chassis.Connect()
                elif hasattr(chassis, 'RefreshInfo'):
                    chassis.RefreshInfo()
                else:
                    print("Warning: No known connect method available, proceeding without explicit connection")
            except Exception as connect_error:
                print("Warning: Chassis connection failed: {}".format(str(connect_error)))
                print("Proceeding with port ownership attempt...")
            # Take ownership of required ports
            for port_location in port_list:
                try:
                    # Use robust port parsing to handle both "1/1" and "1.1" formats
                    card_id, port_id = self._parse_port_location(port_location)

                    if card_id is None or port_id is None:
                        print("Skipping invalid port location: {}".format(port_location))
                        continue
                    # Try to find the card
                    cards = chassis.Card.find()
                    target_card = None
                    for card in cards:
                        if hasattr(card, 'CardId') and str(card.CardId) == str(card_id):
                            target_card = card
                            break
                    if target_card:
                        # Try to find the port
                        ports = target_card.Port.find()
                        target_port = None
                        for port in ports:
                            if hasattr(port, 'PortId') and str(port.PortId) == str(port_id):
                                target_port = port
                                break

                        if target_port:
                            try:
                                # Take ownership - try different methods
                                if hasattr(target_port, 'TakeOwnership'):
                                    target_port.TakeOwnership(Force=True)
                                elif hasattr(target_port, 'ClearOwnership'):
                                    target_port.ClearOwnership()

                                self.owned_ports.append("{}/{}".format(chassis_ip, port_location))
                                print("Successfully handled ownership for port {}/{}".format(chassis_ip, port_location))
                            except Exception as port_error:
                                print("Failed to take ownership of port {}: {}".format(port_location, str(port_error)))
                        else:
                            print("Port {} not found on card {}".format(port_id, card_id))
                    else:
                        print("Card {} not found on chassis {}".format(card_id, chassis_ip))
                except Exception as parse_error:
                    print("Failed to parse port location {}: {}".format(port_location, str(parse_error)))

        except Exception as e:
            print("Port ownership setup failed: {}".format(str(e)))
            # Don't raise exception, continue with degraded functionality
            print("Continuing without port ownership management...")

    def release_port_ownership(self):
        """Release ownership of all owned ports"""
        try:
            print("Releasing port ownership...")
            for port_location in self.owned_ports:
                try:
                    # Parse format: "chassis_ip/card_id/port_id" or "chassis_ip/card_id.port_id"
                    parts = port_location.split('/', 2)
                    if len(parts) != 3:
                        print("Warning: Invalid stored port location format: {}".format(port_location))
                        continue

                    chassis_ip, port_path = parts[0], parts[1] + '/' + parts[2]

                    # Use robust port parsing for the port_path
                    card_id, port_id = self._parse_port_location(port_path)

                    if card_id is None or port_id is None:
                        print("Warning: Could not parse port path '{}' from stored location '{}'".format(port_path, port_location))
                        continue

                    chassis = self.ixnetwork.AvailableHardware.Chassis.find(Hostname=chassis_ip)
                    if chassis:
                        card = chassis.Card.find(CardId=int(card_id))
                        if card:
                            port = card.Port.find(PortId=int(port_id))
                            if port:
                                try:
                                    port.ReleasePort()
                                    print("Released ownership of port {}".format(port_location))
                                except Exception as e:
                                    print("Failed to release port {}: {}".format(port_location, str(e)))
                except Exception as parse_error:
                    print("Failed to parse stored port location {}: {}".format(port_location, str(parse_error)))

            self.owned_ports.clear()
        except Exception as e:
            print("Port ownership release failed: {}".format(str(e)))
            # Don't raise exception, continue with degraded functionality
            print("Continuing without port ownership management...")

    def get_traffic_item_statistics(self, traffic_item_name):
        '''
        ====== Traffic Item Statictics ======
        Row:0  View:Traffic Item Statistics  Sampled:2022-11-22 09:34:13.106614 UTC
            Traffic Item: Traffic-Vrf
            Tx Frames: 80000
            Rx Frames: 60510
            Frames Delta: 19490
            Loss %: 24.363
            Tx Frame Rate: 0.000
            Rx Frame Rate: 0.000
            Tx L1 Rate (bps): 0.000
            Rx L1 Rate (bps): 0.000
            Rx Bytes: 4235700
            Tx Rate (Bps): 0.000
            Rx Rate (Bps): 0.000
            Tx Rate (bps): 0.000
            Rx Rate (bps): 0.000
            Tx Rate (Kbps): 0.000
            Rx Rate (Kbps): 0.000
            Tx Rate (Mbps): 0.000
            Rx Rate (Mbps): 0.000
            Store-Forward Avg Latency (ns): 5383
            Store-Forward Min Latency (ns): 5219
            Store-Forward Max Latency (ns): 6003
            First TimeStamp: 00:00:00.363
            Last TimeStamp: 00:00:00.366
        '''
        caption = "Traffic Item Statistics"
        view = self.session_assistant.StatViewAssistant(caption)
        view.ClearRowFilters()
        rows = view.Rows
        for row in rows:
            if row['Traffic Item'] == traffic_item_name:
                return row

        return None

    def get_port_statistics(self, port_name):
        '''
        Row:0  View:Port Statistics  Sampled:2022-11-21 08:04:35.394276 UTC
            Stat Name: 11.167.132.12/Card01/Port15
            Port Name: 1/1/15
            Line Speed: 200GE
            Link State: Link Up
            Frames Tx.: 107
            Valid Frames Rx.: 7344
            Frames Tx. Rate: 0
            Valid Frames Rx. Rate: 0
            Data Integrity Frames Rx.: 0
            Data Integrity Errors: 0
            Bytes Tx.: 10486
            Bytes Rx.: 521291
            Bits Sent: 83888
            Bits Received: 4170328
            Bytes Tx. Rate: 0
            Tx. Rate (bps): 0.000
            Tx. Rate (Kbps): 0.000
            Tx. Rate (Mbps): 0.000
            Bytes Rx. Rate: 0
            Rx. Rate (bps): 0.000
            Rx. Rate (Kbps): 0.000
            Rx. Rate (Mbps): 0.000
            Scheduled Frames Tx.: 0
            Scheduled Frames Tx. Rate: 0
            Control Frames Tx: 107
            Control Frames Rx: 7265
            Ethernet OAM Information PDUs Sent: 0
            Ethernet OAM Information PDUs Received: 0
            Ethernet OAM Event Notification PDUs Received: 0
            Ethernet OAM Loopback Control PDUs Received: 0
            Ethernet OAM Organisation PDUs Received: 0
            Ethernet OAM Variable Request PDUs Received: 0
            Ethernet OAM Variable Response Received: 0
            Ethernet OAM Unsupported PDUs Received: 0
            Rx Pause Priority Group 0 Frames: 0
            Rx Pause Priority Group 1 Frames: 0
            Rx Pause Priority Group 2 Frames: 0
            Rx Pause Priority Group 3 Frames: 0
            Rx Pause Priority Group 4 Frames: 0
            Rx Pause Priority Group 5 Frames: 0
            Rx Pause Priority Group 6 Frames: 0
            Rx Pause Priority Group 7 Frames: 0
            Misdirected Packet Count: 0
            CRC Errors: 0
            Fragments: 0
            Undersize: 0
            Oversize: 0
        '''
        caption = "Port Statistics"
        view = self.session_assistant.StatViewAssistant(caption)
        view.ClearRowFilters()
        rows = view.Rows
        for row in rows:
            if row['Port Name'] == port_name:
                return row

        return None

    def get_topology_status(self):
        topology = self.ixnetwork.GetTopologyStatus()
        return topology

    def add_traffic_item(self, name, traffic_type="ipv4", traffic_item_type="l2L3"):
        traffic_item = self.ixnetwork.Traffic.TrafficItem.add(
            Name=name, TrafficType=traffic_type, TrafficItemType=traffic_item_type)

        return traffic_item

    def get_all_traffic_items(self):
        return self.ixnetwork.Traffic.TrafficItem.find()

    def get_traffic_item(self, traffic_item_name):
        traffic_items = self.get_all_traffic_items()
        for traffic_item in traffic_items:
            if traffic_item.Name == traffic_item_name:
                return traffic_item

        return None

    def generate_traffic(self):
        self.ixnetwork.Traffic.find().TrafficItem.find().Generate()
        return True

    def traffic_apply(self):
        self.ixnetwork.Traffic.find().Apply()
        return True

    def start_all_stateless_traffic(self):
        self.ixnetwork.Traffic.find().TrafficItem.find().StartStatelessTrafficBlocking()
        return True

    def stop_all_stateless_traffic(self):
        self.ixnetwork.Traffic.find().TrafficItem.find().StopStatelessTrafficBlocking()
        return True

    def start_stateless_traffic(self, traffic_item_name):
        traffic_item = self.get_traffic_item(traffic_item_name)
        if not traffic_item:
            return False

        traffic_item.StartStatelessTrafficBlocking()
        return True

    def stop_stateless_traffic(self, traffic_item_name):
        traffic_item = self.get_traffic_item(traffic_item_name)
        if not traffic_item:
            return False
        traffic_item.StopStatelessTrafficBlocking()
        return True

    def start_all_protocols(self):
        self.ixnetwork.StartAllProtocols()
        return True

    def stop_all_protocols(self):
        self.ixnetwork.StopAllProtocols()
        return True

    def get_topology(self, topology_name):
        res =  self.ixnetwork.Topology.find()
        for item in res:
            if item.Name == topology_name:
                return item

        return None

    def get_device_group(self, topology_name, device_group_name):
        topology = self.get_topology(topology_name)
        if not topology:
            return None

        device_groups = topology.DeviceGroup.find()
        for item in device_groups:
            if item.Name == device_group_name:
                return item
        return None

    def get_ethernet(self, topology_name, device_group_name, ethernet_name):
        device_group = self.get_device_group(topology_name, device_group_name)
        if not device_group:
            return None

        item_list = device_group.Ethernet.find()
        for item in item_list:
            if item.Name == ethernet_name:
                return item
        return None

    def get_ipv4(self, topology_name, device_group_name, ethernet_name,
                 ipv4_name):
        parent_item = self.get_ethernet(topology_name, device_group_name, ethernet_name)
        if not parent_item:
            return None

        item_list = parent_item.Ipv4.find()
        for item in item_list:
            if item.Name == ipv4_name:
                return item
        return None

    def get_ipv4_bgp_peer(self, topology_name, device_group_name, ethernet_name,
                 ipv4_name, bgp_peer_name):
        parent_item = self.get_ipv4(topology_name, device_group_name, ethernet_name,
                                     ipv4_name)
        if not parent_item:
            return None

        item_list = parent_item.BgpIpv4Peer.find()
        for item in item_list:
            if item.Name == bgp_peer_name:
                return item
        return None

    def get_ipv6(self, topology_name, device_group_name, ethernet_name,
                 ipv6_name):
        parent_item = self.get_ethernet(topology_name, device_group_name, ethernet_name)
        if not parent_item:
            return None

        item_list = parent_item.Ipv6.find()
        for item in item_list:
            if item.Name == ipv6_name:
                return item
        return None

    def get_ipv6_bgp_peer(self, topology_name, device_group_name, ethernet_name,
                 ipv4_name, bgp_peer_name):
        parent_item = self.get_ipv6(topology_name, device_group_name, ethernet_name,
                                     ipv4_name)
        if not parent_item:
            return None

        item_list = parent_item.BgpIpv6Peer.find()
        for item in item_list:
            if item.Name == bgp_peer_name:
                return item
        return None

    def get_network_group(self, topology_name, device_group_name, network_group_name):
        device_group = self.get_device_group(topology_name, device_group_name)
        if not device_group:
            return None

        network_groups = device_group.NetworkGroup.find()
        for item in network_groups:
            if item.Name == network_group_name:
                return item
        return None

    def get_ipv4_prefix_pool(self, topology_name, device_group_name, network_group_name, ipv4_prefix_pool_name):
        network_group = self.get_network_group(topology_name, device_group_name, network_group_name)
        if not network_group:
            return None

        ipv4_prefix_pools = network_group.Ipv4PrefixPools.find()
        for item in ipv4_prefix_pools:
            if item.Name == ipv4_prefix_pool_name:
                return item
        return None

    def get_bgp_ip_route_property(self, topology_name, device_group_name, network_group_name, ipv4_prefix_pool_name, birp_name):
        ipv4_prefix_pool = self.get_ipv4_prefix_pool(topology_name, device_group_name, network_group_name, ipv4_prefix_pool_name)
        if not ipv4_prefix_pool:
            return None

        birps = ipv4_prefix_pool.BgpIPRouteProperty.find()
        for item in birps:
            if item.Name == birp_name:
                return item
        return None


    def enable_bgp_ip_route_flapping(self, birp, enable_list, uptime=1, downtime=1, delay=1, partial_flap='true',
                                        flap_from_route_index=1, flap_to_route_index=1):
        birp.EnableFlapping.ValueList(enable_list)
        birp.Uptime.Single(uptime)
        birp.Downtime.Single(downtime)
        birp.Delay.Single(delay)
        birp.PartialFlap.Single(partial_flap)
        birp.FlapFromRouteIndex.Single(flap_from_route_index)
        birp.FlapFromRouteIndex.Single(flap_to_route_index)

    def disable_bgp_ip_route_flapping(self, birp):
        birp.EnableFlapping.Single('false')

    def enable_ipv4_bgp_peer_flapping(self, bgp_peer, uptime_s=10, downtime_s=10):
        if not bgp_peer:
            return False

        bgp_peer.Flap.Single('true')
        bgp_peer.UptimeInSec.Single(uptime_s)
        bgp_peer.DowntimeInSec.Single(downtime_s)
        return True

    def disable_ipv4_bgp_peer_flapping(self, bgp_peer):
        if not bgp_peer:
            return False

        bgp_peer.Flap.Single('false')
        return True

    def enable_ipv6_bgp_peer_flapping(self, bgp_peer, uptime_s=10, downtime_s=10):
        if not bgp_peer:
            return False

        bgp_peer.Flap.Single('true')
        bgp_peer.UptimeInSec.Single(uptime_s)
        bgp_peer.DowntimeInSec.Single(downtime_s)
        return True

    def disable_ipv6_bgp_peer_flapping(self, bgp_peer):
        if not bgp_peer:
            return False

        bgp_peer.Flap.Single('false')
        return True

    def enable_csv_logging(self, caption):
        if caption == "Port Statistics":
            view = self.ixnetwork.Statistics.View.find(Caption="Port Statistics")
            view.update(EnableCsvLogging=True)
        else:
            pass

    def disable_csv_logging(self, caption):
        if caption == "Port Statistics":
            view = self.ixnetwork.Statistics.View.find(Caption="Port Statistics")
            view.update(EnableCsvLogging=False)
        else:
            pass

    def get_csv_file_path(self, caption):
        if caption == "Port Statistics":
            return self.ixnetwork.Statistics.CsvFilePath
        else:
            pass

    def download_file(self, remote_file_name, local_file_name):
        self.session_assistant.Session.DownloadFile(remote_file_name, local_file_name)

    def _parse_port_location(self, port_location):
        """
        Parse port location string to extract card_id and port_id.
        Supports both formats: "1/1" and "1.1"

        Args:
            port_location (str): Port location in format "card/port" or "card.port"

        Returns:
            tuple: (card_id, port_id) as strings, or (None, None) if parsing fails
        """
        try:
            # Normalize the port location by replacing '.' with '/'
            normalized_location = port_location.replace('.', '/')

            # Split by '/'
            parts = normalized_location.split('/')

            if len(parts) != 2:
                print("Error: Port location '{}' must be in format 'card/port' or 'card.port'".format(port_location))
                return None, None

            card_id, port_id = parts

            # Validate that both parts are numeric
            if not (card_id.isdigit() and port_id.isdigit()):
                print("Error: Card ID '{}' and Port ID '{}' must be numeric".format(card_id, port_id))
                return None, None

            return card_id, port_id

        except Exception as e:
            print("Error parsing port location '{}': {}".format(port_location, str(e)))
            return None, None
