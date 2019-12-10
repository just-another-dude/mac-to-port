# Standard Library Modules
import telnetlib  # Used for telnet sessions.
import time  # Used for sleep times.
import re  # Used for regex.
import sys  # Used for exiting the program & commandline arguments.
import subprocess  # Used for pinging on Windows systems.
import os  # Used for pinging on Linux systems.

# Third-Party Modules
import netmiko  # Used for SSH connections.


def check_mac_address(mac_address):
    """
    :param mac_address: MAC address.
    :return: MAC address in lower case after being validated.
    """
    if type(mac_address) != type(""):  # If the type of 'mac_address' isn't a string.
        mac_address = str(mac_address)

    if ":" not in mac_address:
        raise Exception("The MAC address you have entered - {} - doesn't contain colons (:)!".format(mac_address))
    else:
        if len(mac_address) != 17:
            raise Exception("The MAC address you have entered - {} - has an incorrect length".format(mac_address))
        else:
            mac_address = mac_address.lower()

    return mac_address


def change_mac_address(mac_address):
    """
    :param mac_address: MAC address.
    :return: New MAC address in accordance with the switch format of MAC addresses (i.e.: FFFF.FFFF.FFFF)
    """
    if type(mac_address) != type(""):  # If the type of 'mac_address' isn't a string.
        mac_address = str(mac_address)

    mac_address = mac_address.replace(":", "")  # Replace colons with nothing, meaning remove them.

    new_mac_address = ""  # Represents the new MAC address.
    counter = 0
    for character in mac_address:
        counter += 1
        if counter % 4 == 0:  # Add a dot every 4 characters.
            character += "."
        new_mac_address += character

    new_mac_address = new_mac_address.rstrip(".")

    return new_mac_address


def datacenter_and_environment(dc):
    """
    :param dc: Datacenter location and environment.
    :return: String of core switches IP.
    """
    dc_and_env = {
        "site1": "1.1.1.1, 1.1.1.2",
        "site2": "2.2.2.1, 2.2.2.2",
        "site3": "3.3.3.1, 3.3.3.2",
        "site4": "4.4.4.1, 4.4.4.2",
        "site5": "5.5.5.1, 5.5.5.2"
    }
    return dc_and_env[dc]


"""
Telnet function - connection and send command functions.
"""
def telnet_switch(switch, username, password, delay = 1):
        """
        :param switch: Switch IP/DNS to connect to.
        :param username: Username for connecting to the switch.
        :param password: Password for connecting to the switch.
        :param delay: Time interval in seconds for which the data in the terminal will be read from.
        :return: Session object of the specified switch.
        """
        try:
            # Create a session to the switch.
            session = telnetlib.Telnet(switch)
            session.read_until(":")
            session.write(username + "\n")
            session.read_until("Password:", delay)
            session.write(password + "\n")
            session.read_until("#", delay)

            # Disable pagination - output will be shown fully and not sequentially with pages.
            disable_pagination(session)

            # Test connectivity and respond appropriately.
            test_connectivity = telnetlib_send_command(session, "testing connectivity")
            if "Authentication failed" in test_connectivity:
                raise Exception("Authentication has failed for Cisco IOS switch: " + switch)
            elif "Login incorrect" in test_connectivity:
                raise Exception("Authentication has failed for Cisco NX-OS switch: " + switch)
            else:
                print "Connection Established Successfully to Switch: " + switch

        except telnetlib.socket.error as connection_error:
            connection_error = str(connection_error)
            if ("Errno 10061") or ("Errno 111") in connection_error:  # Switch not listening on Telnet port (23).
                session = "Refused"
            elif ("Errno 10060") or ("Errno 110") in connection_error:  # No network connectivity to the switch using Telnet.
                session = "Failed"
            else:
                raise Exception("An unexpected error has occurred - {0} in switch {1}".format(connection_error, switch))

        except Exception as unexpected_error:
            raise Exception("An unexpected error - {} - has occurred in switch {}".format(unexpected_error, switch))

        return session


def disable_pagination(session, command = "terminal length 0\n", delay = 1):
        """
        :param session: Object of an existing session to a switch using the 'telnetlib' module.
        :param command: The command for disabling pagination.
        :param delay: Time in seconds for which output can be read from the switch before returning whatever is found.
        :return: Session with disabled pagination, meaning output will be recorded at once without an interactive UI.
        """
        session.write(command)
        time.sleep(delay)
        session = session.read_until("#", delay)
        return session


def telnetlib_send_command(session, command):
        """
        :param session: Object of an existing Telnet session.
        :param command: The command we want to execute.
        :return: Output of the command.
        """
        session.read_until("#", 8) # Resets the data read from the terminal to the newest line.
        session.write(b"{}\n".format(command))  # The 'b' prefix is ignored, it is for future Python 3 conversion.
        time.sleep(7)  # Wait 7 seconds to allow the output to be fully generated. In some cases, this won't be enough.
        output = session.read_until("#", 30)
        return output


"""
SSH functions - connection and send command.
"""
def ssh_nxos(switch, username, password):
        """
        :param switch: Switch to which we connect.
        :param username: The username with which to connect to the switch.
        :param password: The password with which to connect to the switch.
        :return: Session object to the switch using SSH and dedicated to the NX-OS.
        """
        try:
            session = netmiko.ConnectHandler(
                device_type = "cisco_nxos",
                host = switch,
                username = username,
                password = password
            )

            print "Connection Established Successfully to Switch: {}".format(switch)

        except netmiko.NetmikoTimeoutError:  # No network connectivity - either general or refusal due to protocol.
            ping = check_ping(switch)  # Check network connectivity using ping.
            if ping == True:  # If there is a ping, the connection must have been refused due to the protocol.
                session = "Refused"
            elif ping == False:  # If there is no ping, there is no network connectivity.
                session = "Failed"
            else:
                raise Exception("Unknown option!")

        except netmiko.NetmikoAuthError:  # Authentication to switch failure (bad username/password).
            session = "Authentication failure"

        except Exception as unexpected_error:  # Unexpected error.
            raise Exception("An unexpected error has occurred on switch {}: \n{}".format(switch, unexpected_error))

        return session


def check_ping(switch, system_os = "Linux"):
    """
    :param switch: The switch to ping.
    :return: Boolean value - True if ping is successful, False if unsuccessful.
    """
    if system_os == "Windows":
        ping_output = subprocess.call("ping -n 2 {}".format(switch))
        if ping_output != 0:
            ping = False
        else:
            ping = True
    elif system_os == "Linux":
        ping_output = os.popen("ping -c 2 {}".format(switch))
        time.sleep(10)
        if "0% packet loss" not in ping_output.read():
            ping = False
        else:
            ping = True
    return ping


def ssh_ios(switch, username, password):
        """
        :param switch: The Cisco IOS switch you want to create a session to.
        :param username: The username with which to connect to the switch.
        :param password: The password with which to connect to the switch.
        :return: Session to the switch.
        """
        session = None
        try:
            session = netmiko.ConnectHandler(
                device_type = "cisco_ios",
                host = switch,
                username = username,
                password = password
            )

        except netmiko.NetmikoTimeoutError:  # No network connectivity - either general or refusal due to protocol.
            ping = check_ping(switch)  # Check network connectivity using ping.
            if ping == True:  # If there is a ping, the connection must have been refused due to the protocol.
                session = "Refused"
            elif ping == False:  # If there is no ping, there is no network connectivity.
                session = "Failed"
            else:
                raise Exception("Unknown option!")

        except netmiko.NetmikoAuthError:  # Authentication to switch failure (bad username/password).
            session = "Authentication failure"

        except Exception as unexpected_error:  # Unexpected error.
            raise Exception("An unexpected error has occurred on switch {}: \n{}".format(switch, unexpected_error))

        return session


def netmiko_send_command(session, command):
        """
        :param session: Reference to an existing SSH session opened using the 'netmiko' module.
        :param command: Command to execute using on the specified session.
        :return: Output of the command.
        """
        output = None
        try:
            output = session.send_command(command)
        except AttributeError:
            raise Exception("The session hasn't been properly created!")
        except Exception as unexpected_error:
            raise Exception("Command has failed due to an unexpected error:\n", unexpected_error)
        return output


def telnet_and_ssh(switch, username, password):
    """
    :param switch: Switch IP/DNS for which a session will be created.
    :param username: The username to use for the switch.
    :param password: The password to use for the switch.
    :return connection_type:
    Two possible values:
    1) String "Failed" when connection has failed;
    2) Connection to the switch.
    :return os_version: The OS version of the switch (IOS/NX-OS).
    """
    os_version = None

    # Create a Telnet session.
    telnet_connection = telnet_switch(switch, username, password)
    if telnet_connection == "Refused":  # If the Telnet connection is actively refused (not listening on Telnet port).

        # Create a SSH NX-OS session.
        ssh_nxos_connection = ssh_nxos(switch, username, password)

        if ssh_nxos_connection == "Refused":  # If the SSH connection is refused.
            raise Exception("Both Telnet and SSH connection have been refused!")

        elif ssh_nxos_connection == "Failed":  # No network connectivity, possibly wrong IP.
            connection_type = "Failed"

        else:  # If everything is fine (as supposed to be)...
            version = check_version(ssh_nxos_connection, is_telnet = False)  # Check OS version.
            if version == "IOS":
                ssh_nxos_connection.disconnect()  # Disconnect from the session.
                ssh_ios_connection = ssh_ios(switch, username, password)  # Create a new SSH IOS session.
                if ssh_ios_connection == "Refused":  # If the SSH connection is refused.
                    raise Exception("SSH Connection has unexpectedly been refused. Switch: ", switch)

                elif ssh_ios_connection == "Failed":
                    raise Exception("SSH connection has unexpectedly failed. Switch: ", switch)

                else:  # If everything is fine (supposed to be)
                    connection_type = ssh_ios_connection
                    os_version = version

            elif version == "NX-OS":
                connection_type = ssh_nxos_connection
                os_version = version

            else:
                raise Exception("Unrecognized switch version on switch: ", switch)

    elif telnet_connection == "Failed":  # If the the IP hasn't responded.
        connection_type = "Failed"

    elif telnet_connection == None:  # If for some reason a session hasn't been created and no exception was risen.
        raise Exception("An unprecedented error has occurred, please check the telnet connection function!"
                        "\nSwitch: {0}".format(switch))

    else:  # If everything is fine (supposed to be).
        version = check_version(telnet_connection, is_telnet = True)
        connection_type = telnet_connection
        os_version = version

    return (connection_type, os_version)


def check_version(session, is_telnet):
    """
    :param session: The session to the switch.
    :param is_telnet: Session's connection protocol - True for Telnet, False for SSH.
    :return: The switch OS version (IOS/NX-OS).
    """
    # If the session uses Telnet...
    if is_telnet == True:
        version = telnetlib_send_command(session, command = "show version")
        version = str(version.split("\n")[:3])  # OS should be in the first two lines of the output.
        if "IOS" in version:
            switch_version = "IOS"
        else:
            switch_version = "NX-OS"

    # If the session is NOT in Telnet, meaning SSH...
    elif is_telnet == False:
        version = netmiko_send_command(session, command = "show version")
        version = str(version.split("\n")[:3])  # OS should be in the first two lines of the output.
        if "IOS" in version:
            switch_version = "IOS"
        else:
            switch_version = "NX-OS"

    # If the session is not in telnet/SSH (aka not True/False)...
    else:
        raise Exception("The argument 'is_telnet' must have a boolean value!")

    return switch_version


def find_mac(session, mac_address, is_telnet, os_version):
    """
    :param session: The session to the switch.
    :param is_telnet: If telnet - True, if SSH - False.
    :param os_version: Switch OS version - Cisco IOS or Cisco NX-OS.
    :return: Interface with the specified MAC and the interface type (Regular / Port Channel).
    """
    # If the session is Telnet...
    if is_telnet == True:
        if os_version == "IOS":
            mac_record = telnetlib_send_command(session, "show mac-address-table | include {0}".format(mac_address))
            mac_record = str(mac_record)
            if len(mac_record) != 0:  # If there is output.
                if "Invalid" in mac_record:  # Some versions have a different syntax.
                    mac_record = telnetlib_send_command(session, "show mac address-table |"
                                                                 " include {0}".format(mac_address))
                interface = mac_record.rstrip("\r\n").split(" ")[-1]  # The port on which the MAC is found on.
            else:  # If there is no output.
                interface = "Not Found"
        elif os_version == "NX-OS":
            mac_record = telnetlib_send_command(session, "show mac address-table | grep -i {0}".format(mac_address))
            mac_record = str(mac_record)
            if mac_record != 0:  # If there is output.
                if "Invalid" in mac_record: # In case of different syntax.
                    mac_record = telnetlib_send_command(session, "show mac-address-table |"
                                                                 " grep -i {0}".format(mac_address))
                interface = mac_record.rstrip("\r\n").split(" ")[-1]  # The port on which the MAC is found on.
            else:  # If there is no output.
                interface = "Not Found"
        else:
            raise Exception("The value of the argument 'os_version' is incorrect: ", os_version)

    # If the session is SSH...
    elif is_telnet == False:
        if os_version == "IOS":
            mac_record = netmiko_send_command(session, "show mac-address-table | include {0}".format(mac_address))
            mac_record = str(mac_record)
            if len(mac_record) != 0:  # If there is output.
                if "Invalid" in mac_record:  # Some versions have a different syntax.
                    mac_record = netmiko_send_command(session, "show mac address-table |"
                                                                 " include {0}".format(mac_address))
                interface = mac_record.rstrip("\r\n").split(" ")[-1]  # The port on which the MAC is found on.
            else:  # If there is no output.
                interface = "Not Found"

        elif os_version == "NX-OS":
            mac_record = netmiko_send_command(session, "show mac address-table | grep -i {0}".format(mac_address))
            mac_record = str(mac_record)
            if len(mac_record) != 0:  # If there is output.
                if "Invalid" in mac_record:
                    mac_record = netmiko_send_command(session, "show mac-address-table |"
                                                               " grep -i {}".format(mac_address))
                interface = mac_record.rstrip("\r\n").split(" ")[-1]  # The port on which the MAC is found on.
            else:  # If there is no output.
                interface = "Not Found"
        else:
            raise Exception("The value of the argument 'os_version' is incorrect: ", os_version)

    # If the session is not Telnet nor SSH (aka value is not True/False)...
    else:
        raise Exception("The value of the argument 'is_telnet' is incorrect: ", is_telnet)

    interface = str(interface)
    if "Po" in interface:
        interface_type = "Port-Channel"
    elif "Not Found" in interface:
        interface_type = None
    else:
        interface_type = "Regular"

    return (interface, interface_type)


def interface_syntax(port):
    """
    :param port: An interface which needs to be filtered for the correct syntax.
    :return: The correct interface syntax.
    """
    # Regex for checking the port syntax.
    interface = None

    # Pattern list containing all of the possible port names that should exist.
    pattern_list = ["Po\d+",
                    "Eth\d+/\d+/\d+", "Eth\d+/\d+",
                    "Gi\d+/\d+/\d+", "Gi\d+/\d+",
                    "Te\d+/\d+/\d+", "Te\d+/\d+",
                    "Fa\d+/\d+\d+","Fa\d+/\d+"]
    for pattern in pattern_list:
        try:
            interface = re.search(pattern, port).group()
            break
        except:  # In case pattern was not found.
            continue
    return interface


def portchannel_interfaces(session, portchannel, os_version, is_telnet):
    """
    :param session: Reference to the session with the switch.
    :param portchannel: The port channel which needs to be checked.
    :param os_version: The OS version of the switch.
    :param is_telnet: If the session is open with Telnet/SSH.
    :return: An interface (one of possible many) from the port channel.
    """
    if is_telnet == True:
        if os_version == "IOS":
            etherchannel_records = telnetlib_send_command(session, "show etherchannel summary | include {0}"
                                                         .format(portchannel))
            # Several port channels may be matched (i.e. include Po1 may also be Po10), therefore store the first line.
            etherchannel_record = etherchannel_records.split("\r\n")[1]  # First port channel found.
            interface = etherchannel_record.split()[-2:]  # Two of the last elements, should be the ports.

        elif os_version == "NX-OS":
            # -w flag in grep matches a specific expression, thus avoiding the problem we have with 'include' for IOS.
            portchannel_record = telnetlib_send_command(session, "show port-channel summary | grep -w {0}"
                                                      .format(portchannel))
            interface = portchannel_record.split()[-2:]

        else:
            raise Exception("Unknown option!")

    elif is_telnet == False:
        if os_version == "IOS":
            etherchannel_records = netmiko_send_command(session, "show etherchannel summary | include {0}"
                                                         .format(portchannel))
            # In netmiko (unlike telnetlib), the command is not included in the output.
            etherchannel_record = etherchannel_records.split("\r\n")[0]  # First line of output.
            interface = etherchannel_record.split()[-2:]

        elif os_version == "NX-OS":
            portchannel_record = netmiko_send_command(session, "show port-channel summary | grep -w {0}"
                                                      .format(portchannel))
            interface = portchannel_record.split()[-2:]

        else:
            raise Exception("Unknown option!")

    else:
        raise Exception("Unknown option!")

    return str(interface)


def ip_regex(ip_string):
    """
    :param ip_string: String that should contain an IP address (possibly amongst other things).
    :return: String with the IP address or a string stating multiple IPs have been found.
    """
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    ip_list = re.findall(pattern, ip_string)
    if len(ip_list) == 0:  # No IPs.
        ip = None
    elif len(ip_list) == 1:  # One IP.
        ip = ip_list[0]
    else:  # More than 2 IPs.
        ip = "Multiple IPs"
    return ip


def cdp_table(session, os_type, is_telnet, interface):
    """
    :param session: The session to the switch.
    :param os_type: The OS version of the switch.
    :param is_telnet: Connection type (Telnet / SSH).
    :param interface: The interface to check in the CDP table.
    :return switch_ip: A list with elements that may be - 1) None; 2) String of an IP; 3) String stating "Multiple IPs".
    :return device_name: String of the switch device name connected to the inputted interface.
    """
    # Switch IP list.
    switch_ip = []

    # Change the interface syntax to comply with the switch CDP table standards.
    interface = interface_syntax_for_cdp(interface, os_type)

    # Check the CDP table according to protocol & OS type.
    if is_telnet == True:
        if os_type == "IOS":
            telnetlib_send_command(session, "free")
            cdp_entry = telnetlib_send_command(session, "show cdp neighbors {}".format(interface))
            cdp_entry_list = cdp_entry.split("\n")[3:]
            device_id = None

            # Case insensitive switch names, all conventional switch names should match one of the patterns.
            device_regex = [r"(?i)cat\w+", r"(?i)sw\w+", r"(?i)nex\w+"]

            # Try matching the switch name with one of the patterns.
            exit_loop = None
            for line in cdp_entry_list:
                if exit_loop == True:
                    break
                for device in device_regex:
                    try:
                        device_id = re.search(device, line).group(0)
                        if "sw" or "cat" in device_id:
                            # Add a dot after the switch name to exclude possibility of multiple switches matching.
                            # For example, when searching "swc7", "swc70", "swc71", "swc72" etc. will also match.
                            # However, as an example for "swc7.", only "swc7.site" will match.
                            device_id += "\."
                        exit_loop = True
                        break
                    except AttributeError:  # If there's no match...
                        continue
                    except Exception as unexpected_error:
                        raise Exception("Unexpected error has occurred: {}".format(unexpected_error))

            # CDP details table where we can see more information about the switch connected to the interface.
            cdp_details = telnetlib_send_command(session, "show cdp neighbors detail | beg {}".format(device_id))
            # Remove "Device ID:" prefix, thereby leaving only the switch name itself.
            device_name = cdp_details.split("\r\n")[1].replace("Device ID: ", "")
            cdp_details_entry = cdp_details[:200]
            if ip_regex(cdp_details_entry) == None or ip_regex(cdp_details_entry) == "Multiple IPs":
                pass
            else:
                switch_ip.append(ip_regex(cdp_details_entry))  # Should append specific IP.

        elif os_type == "NX-OS":
            '''
            A problem occurs where the output is not read properly:
            The previous command is read instead of the output itself,
            therefore the same command is sent so that the next one will receive the output of the previous command.
            Maybe increasing the "telnetlib.read_until" method's timeout argument will remedy this.
            Further testing is required with the help of the "telnetlib" module documentation.
            '''
            # Send the same command twice and store the output of the first one in the second one,
            # due to the bug described above.
            # This command finds the CDP detailed entry for the interface with 15 lines after the interface
            # which should cover the entry and allow us to find the Management IP address.
            telnetlib_send_command(session, "show cdp neighbors detail | grep -A 15 -i {}".format(interface))
            cdp_entry = telnetlib_send_command(session = session, command = 'show cdp neighbors detail'
                                                                            ' | grep -A 15 -i {}'.format(interface))

            if ip_regex(cdp_entry) == None or ip_regex(cdp_entry) == "Multiple IPs":
                pass
            else:
                switch_ip.append(ip_regex(cdp_entry))  # Should append the management IP address.

            # Get another IP if found.
            interface_ip = telnetlib_send_command(session = session, command = 'show cdp neighbors detail |'
                                                                                ' grep -B 5 -i {}'.format(interface))
            if ip_regex(interface_ip) == None or ip_regex(interface_ip) == "Multiple IPs":
                pass
            else:  # If a specific IP is returned
                switch_ip.append(ip_regex(interface_ip))

            # CDP details.
            cdp_device_id = telnetlib_send_command(session = session, command = 'show cdp neighbors detail |'
                                                                                ' grep -B 10 -i {}'.format(interface))
            # Get switch name.
            try:
                device_id = re.search(pattern = "Device ID:.+\n", string = cdp_device_id).group()
                if "(" and ")" in device_id:  # Usually Nexus switch device IDs contain something in parenthesis.
                    # Remove the parenthesis and their content from the switch device name.
                    device_id = device_id.replace(re.search("\(.+\)", device_id).group(), "")
                device_name = device_id.replace("Device ID:", "").replace("\n", "")  # Remove "Device ID:" prefix.
            except AttributeError:  # If no match occurs.
                device_name = None
            except Exception as unexpected_error:
                raise Exception("Unexpected error has occurred: ", unexpected_error)

        else:
            raise Exception("Wrong OS type!")

    elif is_telnet == False:
        if os_type == "IOS":
            netmiko_send_command(session, "free")  # Random command for terminal recalibration (exclude output bugs).

            # Detailed CDP entry for the specified interface.
            cdp_entry = netmiko_send_command(session, "show cdp neighbors {}".format(interface))
            cdp_entry_list = cdp_entry.split("\n")[3:]  # Relevant information starts from line 4.
            device_id = None

            # Match the device ID with a switch name.
            device_regex = [r"(?i)cat\w+", r"(?i)sw\w+", r"(?i)nex\w+"]  # Case insensitive conventional switch names.
            exit_loop = None
            for line in cdp_entry_list:
                if exit_loop == True:
                    break
                for device in device_regex:
                    try:
                        device_id = re.search(device, line).group(0)
                        if "cat" or "sw" in str(device_id):
                            # Used for placing a dot after the switchname to find the correct switch in the CDP table.
                            # When matching without a dot we may match many switches with the same beginning.
                            device_id += "\."
                        exit_loop = True
                        break
                    except AttributeError:
                        continue
                    except Exception as unexpected_error:
                        raise Exception("Unexpected error has occurred: ", unexpected_error)

            # CDP details, for explanation go to the 'is_telnet == True' condition above.
            cdp_details = netmiko_send_command(session, "show cdp neighbors detail | beg {}".format(device_id))
            device_name = cdp_details.split("\r\n")[1].replace("Device ID: ", "")
            cdp_details_entry = cdp_details[:200]

            # Match a switch IP from the output and append it.
            if ip_regex(cdp_details_entry) == None or ip_regex(cdp_details_entry) == "Multiple IPs":
                pass
            else:
                switch_ip.append(ip_regex(cdp_details_entry))

        elif os_type == "NX-OS":
            # Find CDP details - hostname and switch IPs.
            cdp_entry = netmiko_send_command(session = session, command = 'show cdp neighbors detail |'
                                                                            ' grep -A 15 -i {}'.format(interface))

            if ip_regex(cdp_entry) == None or ip_regex(cdp_entry) == "Multiple IPs":
                pass
            else:
                switch_ip.append(ip_regex(cdp_entry))  # Should append management IP.

            # Get another IP if found.
            interface_ip = netmiko_send_command(session = session, command = 'show cdp neighbors detail |'
                                                                                ' grep -B 5 -i {}'.format(interface))
            if ip_regex(interface_ip) == None or ip_regex(interface_ip) == "Multiple IPs":
                pass
            else:
                switch_ip.append(ip_regex(interface_ip))  # Should append interface IP.

            # CDP details.
            cdp_device_id = netmiko_send_command(session = session, command = 'show cdp neighbors detail |'
                                                                                ' grep -B 10 -i {}'.format(interface))
            try:
                device_id = re.search(pattern = "Device ID:.+\n", string = cdp_device_id).group()
                if "(" and ")" in device_id:
                    device_id = device_id.replace(re.search("\(.+\)", device_id).group(), "")
                device_name = device_id.replace("Device ID:", "").replace("\n", "")
            except AttributeError:
                device_name = None
            except Exception as unexpected_error:
                raise Exception("Unexpected error has occurred: ", unexpected_error)

        else:
            raise Exception("Unknown option!")

    else:
        raise Exception("Unknown option!")

    return (switch_ip, device_name)


def interface_syntax_for_cdp(interface, os_version):
    """
    :param interface: Interface input to change syntax for CDP usage.
    :param os_version: The OS version of the switch (i.e. IOS/NX-OS).
    :return: The newly changed interface according to the necessary syntax for CDP.
    """
    interface = str(interface)

    if os_version == "IOS":
        if "Eth" in interface:
            interface = interface.replace("Eth", "Ethernet")
        elif "Gi" in interface:
            interface = interface.replace("Gi", "GigabitEthernet")
        elif "Te" in interface:
            interface = interface.replace("Te", "TenGigabitEthernet")

    elif os_version == "NX-OS":
        if "Eth" in interface:
            interface = interface.replace("Eth", "Ethernet")

    else:
        raise Exception("Unknown option!")

    return interface


def check_port_mode(port, session, is_telnet):
    """
    :param port: The interface which is going to be checked.
    :param session: Session to the switch.
    :param is_telnet: True - Telnet, False - SSH.
    :return: Port mode (Access / Trunk) in a string.
    """
    if is_telnet == True:
        port_config = telnetlib_send_command(session, "show run int {}".format(port))  # Port running config.
        if "access" in port_config:
            port_mode = "Access"
        elif "trunk" in port_config:
            port_mode = "Trunk"
        else:
            interface_config = telnetlib_send_command(session, "show int {}".format(port))  # Port hardware config.
            if "access" in interface_config:
                port_mode = "Access"
            elif "trunk" in interface_config:
                port_mode = "Trunk"
            else:  # If not Trunk / Access
                port_mode = None

    elif is_telnet == False:
        port_config = netmiko_send_command(session, "show run int {}".format(port))  # Port running config.
        if "access" in port_config:
            port_mode = "Access"
        elif "trunk" in port_config:
            port_mode = "Trunk"
        else:
            interface_config = netmiko_send_command(session, "show int {}".format(port))  # Port hardware config.
            if "access" in interface_config:
                port_mode = "Access"
            elif "trunk" in interface_config:
                port_mode = "Trunk"
            else:  # If not Trunk / Access
                port_mode = None

    else:
        raise Exception("Unknown option!")

    return port_mode


def track_mac(username, password, session, os_version, mac_address):
    """
    :param username: RADIUS username for connecting to switches.
    :param password: RADIUS password for connecting to switches.
    :param session: An active session to a switch.
    :param os_version: OS version of the switch.
    :param mac_address: MAC address the server we are tracking.
    :return: This function runs recursively, exiting only when it finds the access port to which a switch is connected.
    """
    # Check the session protocol, and find hostname.
    if "netmiko" in str(session):  # SSH session.
        is_telnet = False
        print "Session is using SSH via the 'netmiko' module!"
        hostname = session.find_prompt()  # Switch hostname.
        # session.disconnect()
    elif "telnet" in str(session):  #  Telnet session.
        is_telnet = True
        print "Session is using Telnet via the 'telnetlib' module!"
        hostname = telnetlib_send_command(session, "\n").replace("\n", "")  # Switch hostname.
        # session.get_socket().shutdown(socket.SHUT_WR)
    else:
        raise Exception("Unknown connection type!")

    # Find the interface and its type corresponding to the inputted MAC address.
    interface_info = find_mac(session = session, os_version = os_version,
                              mac_address = mac_address, is_telnet = is_telnet)
    port = interface_info[0]  # The interface itself.
    port_type = interface_info[1]  # The type of the interface - should be Port-Channel or Regular.

    # Format the port syntax according to switch standards.
    port_syntax = interface_syntax(port)

    # Print out the port that was found along with the switch it was found on.
    print("The MAC has been found on port {} on switch: ".format(port_syntax))
    print hostname

    if port_type == "Regular":
        # Supposed to be access port...
        if port_syntax == None:  # If a port has not been found...
            raise Exception("The inserted MAC address has not been found in the database!")

        # Check the port mode --> Access / Trunk.
        port_mode = check_port_mode(port = port_syntax, session = session, is_telnet = is_telnet)

        if port_mode == "Access":  # Access port to which the server should be connected to.
            print("Server should be connected to this access port: {} on switch:".format(port_syntax))
            print hostname
            sys.exit()

        elif port_mode == "Trunk":  # Trunk port that's either connected to another switch or to a Flex / possibly FI.
            switch_port = port_syntax
            print "The port {} is configured as trunk and not in a portchannel on switch: {}"\
                .format(switch_port, hostname)
            switch_ip_and_name = cdp_table(session = session, os_type = os_version,
                                            is_telnet = is_telnet, interface = switch_port)
            switch_ip_list = switch_ip_and_name[0]
            switch_name = switch_ip_and_name[1]

            if len(switch_ip_list) == 0:
                print("The interface {} is probably connected to a Flex Fabric,"
                      " configured as trunk and has no CDP neighbors on switch: ".format(switch_port))
                print hostname
                sys.exit()

            else:  # May contain a list of IPs.
                pass

        else:
            raise Exception("Unknown option!")


    elif port_type == "Port-Channel":  # Supposed to connect to another switch.
        # Retrieve an interface from the port channel.
        switch_port = portchannel_interfaces(session = session, is_telnet = is_telnet,
                                             os_version = os_version, portchannel = port)
        switch_port = interface_syntax(switch_port)

        # Retrieve switch name & corresponding IP list.
        switch_ip_and_name = cdp_table(session = session, os_type = os_version,
                                       is_telnet = is_telnet, interface = switch_port)
        switch_ip_list = switch_ip_and_name[0]
        print "Neighboring switch IP list: ", switch_ip_list
        switch_name = switch_ip_and_name[1]

        if len(switch_ip_list) == 0:
            raise Exception("No Switch IP has been found for portchannel {} on switch {}".format(port, hostname))

        else:  # switch_ip_list should contain a list of IPs.
            pass

    else:
        # Anything else
        raise Exception("Unknown option, probably MAC not found!\n"
                        "Also try increasing sleep time when waiting for command output")

    counter = 0
    new_os_version = None
    new_session = None
    for switch_ip in switch_ip_list:
        counter += 1
        new_connection = telnet_and_ssh(switch_ip, username, password)
        new_session = new_connection[0]
        new_os_version = new_connection[1]

        if new_session == "Failed":
            if counter == len(switch_ip_list):  # If this is the last IP in the list.
                new_connection = telnet_and_ssh(switch_ip, username, password)
                new_session = new_connection[0]
                new_os_version = new_connection[1]

                if new_session == "Failed":
                    print "Session creation with IP has failed, now trying with DNS: ", switch_name
                    new_connection = telnet_and_ssh(switch_name, username, password)
                    new_session = new_connection[0]
                    new_os_version = new_connection[1]

                    if new_session == "Failed":
                        '''
                        OPTIONAL ADDITION:
                        A static text file with all of the switch IPs and DNS.
                        Write a function that will match the switch name with its IP and try to connect once more.
                        '''
                        raise Exception("Both the IP and the Device Name could not be reached!")
                    else:  # Successfully connected to DNS.
                        break

                else:  # Successfully connected to IP.
                    break

            # Try creating a new connection with a different IP.
            new_connection = telnet_and_ssh(switch_name, username, password)
            new_session = new_connection[0]
            new_os_version = new_connection[1]

            if new_session == "Failed":
                continue
            else:  # Successfully connected with a different IP.
                break
        else:  # Successful connection
            break


    track_mac(username = username, session = new_session,
              password = password, os_version = new_os_version,
              mac_address = mac_address)


def main():
    # Variables
    dc_and_env = sys.argv[1]  # raw_input("Enter the dc and env: ")  # Datacenter and environment.
    username = sys.argv[2]  # raw_input("Enter the username for switches: ")  # RADIUS/Local username.
    password = sys.argv[3]  # raw_input("Enter the password for switches: ")  # RADIUS/Local password.
    mac_address = sys.argv[4]  # raw_input("Enter the MAC address: ")  # Original MAC Address.
    session = None  # Represents the session to a switch.
    os_version = None  # Represents the OS version of the switch.

    # MAC validity & generation.
    mac_address = check_mac_address(mac_address)  # Check MAC address validity.
    mac_address = change_mac_address(mac_address)  # Generate new MAC in accordance with Switch standards.

    # Create a list of core switches according to the datacenter location and environment.
    core_ips = datacenter_and_environment(dc_and_env)  # Get string of core switches according to the DC & Environment.
    core_switches = core_ips.split(", ")  # Create a list of core switches from the 'core_ips' string.

    # Run a for loop attempting connection to a core and break when successful, raise Exception if not.
    switch_counter = 0
    for core in core_switches:
        switch_counter += 1
        connection = telnet_and_ssh(core, username, password)  # Create a session to a core switch.
        session = connection[0]
        os_version = connection[1]

        if session == None or session == "Failed":  # If a connection to the first core has failed, go to the next.
            if switch_counter == len(core_switches):  # Last switch in the list.
                raise Exception("Connection to all the core switches has failed!")
            else:
                continue
        else:
            break

    # Start recursive (switch to switch) MAC search to find the access switch & port.
    track_mac(username = username, password = password, session = session,
              os_version = os_version, mac_address = mac_address)


if __name__ == '__main__':
    main()
