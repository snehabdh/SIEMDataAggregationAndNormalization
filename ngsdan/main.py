from imports import *



#################> PATHS <######################
UFW_LOG_FILE_PATH = '/var/log/ufw.log'  # Path to UFW log file
AUTH_LOG_FILES_PATH = ['/var/log/syslog', '/var/log/auth.log']  # Paths to log files
DPKG_LOG = "/var/log/dpkg.log"
APT_HISTORY_LOG = "/var/log/apt/history.log"
AUTH_LOG = "/var/log/auth.log"




#################> PATTERNS <######################
port_scan_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2}) .*? \[UFW (BLOCK|ALLOW|AUDIT)\] .*? SRC=(\d+\.\d+\.\d+\.\d+) DST=(\d+\.\d+\.\d+\.\d+)'
AUTH_LOG_event_pattern = re.compile(
    r"""
    ^
    (?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2})  # Timestamp
    \s+(?P<hostname>[\w\-.]+)                                              # Hostname
    \s+(?P<process>\S+)\[(?P<pid>\d+)\]:                                   # Process name and PID
    \s+(?P<log_text>.+)                                                    # Log text
    $
    """,
    re.VERBOSE
)



# Regex pattern to match USB connect/disconnect events
USB_event_pattern = re.compile(
    r'''
    ^
    (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2})  # Timestamp
    \s+\S+                                                 # Hostname
    \s+kernel:                                             # Kernel marker
    \s+usb\s+\S+:\s+                                        # USB device identifier
    (.*?)                                                   # Event description
    $
    ''',
    re.VERBOSE | re.MULTILINE
)

auth_event_pattern = re.compile(
    r"""
    ^
    (?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2})  # Timestamp
    \s+(?P<hostname>[\w\-.]+)                                              # Hostname
    \s+(?P<process>\S+)\[(?P<pid>\d+)\]:                                   # Process name and PID
    \s+(?P<log_text>.+)                                                    # Log text
    $
    """,
    re.VERBOSE
)



#################> VARIABLES <######################
#PORT SCAN
port_scan_connection_attempts = defaultdict(deque)
TIME_WINDOW_FOR_PORT_SCAN = timedelta(minutes=1)  # Time range for scan detection (15 seconds)
PORT_SCAN_last_cleanup_time = datetime.now()  # Variable to track the last cleanup time
# Cooldown period for alerts from the same IP address (in seconds)
PORT_SCAN_ALERT_TIMEOUT = timedelta(minutes=1)
PORT_SCAN_last_alert_time = {}  # Track last alert time for each source IP


# Configure logging to a file
logging.basicConfig(
    filename='main.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Function to read network statistics with packet counts
def read_network_stats():
    with open('/proc/net/dev', 'r') as f:
        lines = f.readlines()[2:]  # Skip headers

    stats = {}
    for line in lines:
        parts = line.split()
        interface = parts[0].strip(':')
        rx_bytes = int(parts[1])   # Received bytes
        rx_packets = int(parts[2]) # Received packets
        tx_bytes = int(parts[9])   # Transmitted bytes
        tx_packets = int(parts[10])# Transmitted packets

        stats[interface] = {
            'rx': rx_bytes,
            'tx': tx_bytes,
            'packets': rx_packets + tx_packets  # Total packets
        }
    
    return stats

# Function to get MAC and IP addresses for all interfaces using psutil
def get_interface_info():
    interface_info = {}
    try:
        # Get MAC and IP addresses using psutil
        nics = psutil.net_if_addrs()
        for interface in nics:
            ip_address = None
            mac_address = None

            for addr in nics[interface]:
                if addr.family == socket.AF_INET:  # IPv4 address family
                    ip_address = addr.address
                elif addr.family == psutil.AF_LINK:  # MAC address family
                    mac_address = addr.address

            interface_info[interface] = {'ip': ip_address, 'mac': mac_address}

    except Exception as e:
        logging.error(f"Error retrieving interface information: {e}")

    return interface_info

interface_info = get_interface_info()


# GET MAC address
def get_mac_address():
    try:
        # Get the MAC address
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)[::-1]])

        return  mac_address

    except Exception as e:
        print(f"Error getting MAC: {e}")
        return ""

# Function to get the device IP
def get_device_ip():
    try:
        # Get the hostname
        host_name = socket.gethostname()
        # Get the IP address associated with the hostname
        ip_address = socket.gethostbyname(host_name)
        # print(ip_address)
        return ip_address
    except Exception as e:
        print(f"Error getting device IP: {e}")
        return ""
    
    

    
# Function to generate a unique event ID (you can use a better method if needed)
event_id_counter = 0
def generate_event_id():
    global event_id_counter
    event_id_counter += 1
    return event_id_counter

#SAVE LOG AND PROCEED FOR BINARY PACKET
def log_event(component, resource, log_text, event_reason, mac_address, ip_address,event_type,event_subtype):
    current_time = datetime.now()

    structured_data = {
        'event_id': generate_event_id(),
        'date': current_time.day,
        'month': current_time.month,
        'year': current_time.year,
        'hh': current_time.hour,
        'mm': current_time.minute,
        'ss': current_time.second,
        'event_type': event_type,
        'event_sub_type': event_subtype,
        'component': component,
        'user': getpass.getuser(),
        'resource': resource,
        'log_text': log_text,
        'event_reason': event_reason,
        'pid': os.getpid(),
        'device_type': PC,  # Assuming 1 represents PC as per your LogConstants
        'device_macId': str(mac_address) if mac_address else '',
        'device_ip': str(ip_address) if ip_address else ''
    }

    # Log the structured data as an info message
    logging.info(structured_data)

    # Send structured data as a UDP packet
    send_udp_packet(structured_data)

#SEND BINARY PACKET TO THE SERVER
def send_udp_packet(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Prepare byte array to send
        byte_array = bytearray()

        # Pack the data byte by byte
        byte_array.extend(data['event_id'].to_bytes(4, byteorder='big'))
        byte_array.append(data['date'])
        byte_array.append(data['month'])
        byte_array.extend(data['year'].to_bytes(2, byteorder='little'))
        byte_array.append(data['hh'])
        byte_array.append(data['mm'])
        byte_array.append(data['ss'])
        byte_array.append(data['event_type'])
        byte_array.append(data['event_sub_type'])
        byte_array.append(data['component'])
        byte_array.extend(data['user'].encode('utf-8').ljust(50, b'\0'))
        byte_array.extend(data['resource'].encode('utf-8').ljust(50, b'\0'))
        byte_array.extend(data['log_text'].encode('utf-8').ljust(100, b'\0'))
        byte_array.extend(data['event_reason'].encode('utf-8').ljust(80, b'\0'))
        byte_array.extend(data['pid'].to_bytes(4, byteorder='big'))
        byte_array.append(data['device_type'])
        byte_array.extend(data['device_macId'].encode('utf-8').ljust(20, b'\0'))
        byte_array.extend(data['device_ip'].encode('utf-8').ljust(15, b'\0'))

        sock.sendto(byte_array, (UDP_IP, UDP_SERVER_PORT))
    except Exception as e:
        logging.error(f"Error sending UDP packet: {e}")
    finally:
        sock.close()



#MONITOR HIGH VOLUME DATA TRANBSFER
def HVDT():
    print("HVDT")

    previous_stats = read_network_stats()
    time.sleep(TIME_RANGE)

    interface_info = get_interface_info()

    while True:
        current_stats = read_network_stats()

        for interface in current_stats:
            rx_diff = current_stats[interface]['rx'] - previous_stats[interface]['rx']
            tx_diff = current_stats[interface]['tx'] - previous_stats[interface]['tx']

            if rx_diff > DOWNLOAD_THRESHOLD or tx_diff > UPLOAD_THRESHOLD:
                mac_address = interface_info.get(interface, {}).get('mac', '')
                ip_address = interface_info.get(interface, {}).get('ip', '')

                reason_parts = []
                if rx_diff > DOWNLOAD_THRESHOLD:
                    reason_parts.append(f"Excessive download: {rx_diff} bytes")
                if tx_diff > UPLOAD_THRESHOLD:
                    reason_parts.append(f"Excessive upload: {tx_diff} bytes")

                event_reason = " | ".join(reason_parts)

                log_event(
                    component=1,  # Assuming 1 represents this component
                    resource=interface,
                    log_text='High volume data transfer detected on interface {}'.format(interface),
                    event_reason=event_reason,
                    mac_address=mac_address,
                    ip_address=ip_address,
                    event_type=NetworkActivityEvents,
                    event_subtype=HighVolumeDataTransfer,
                )

        previous_stats = current_stats
        time.sleep(TIME_RANGE)

# Main monitoring loop
def DOS():
    print("DoS")

    previous_stats = read_network_stats()
    # print('prev: ',previous_stats)

    packet_count_map = {interface: 0 for interface in interface_info.keys()}

    while True:          
        current_stats = read_network_stats()

        for interface in current_stats:
            packet_count_map[interface] = (current_stats[interface]['packets'] - previous_stats[interface]['packets'])
            
            # Prepare to check system resource usage for DoS detection
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent
            disk_usage = psutil.disk_usage('/').percent

            reasons_for_dos_detection = []

            rx_diff = current_stats[interface]['rx'] - previous_stats[interface]['rx']
            tx_diff = current_stats[interface]['tx'] - previous_stats[interface]['tx']

            if rx_diff > DOWNLOAD_THRESHOLD:
                reasons_for_dos_detection.append(f"Excessive download: {rx_diff} bytes")

            if tx_diff > UPLOAD_THRESHOLD:
                reasons_for_dos_detection.append(f"Excessive upload: {tx_diff} bytes")

            if packet_count_map[interface] > PACKET_COUNT_THRESHOLD:
                reasons_for_dos_detection.append(f"Packet count exceeded: {packet_count_map[interface]}")

            if cpu_usage > CPU_USAGE_THRESHOLD:
                reasons_for_dos_detection.append(f"CPU usage exceeded: {cpu_usage}%")

            if memory_usage > MEMORY_USAGE_THRESHOLD:
                reasons_for_dos_detection.append(f"Memory usage exceeded: {memory_usage}%")

            if disk_usage > DISK_USAGE_THRESHOLD:
                reasons_for_dos_detection.append(f"Disk usage exceeded: {disk_usage}%")

            # Log DoS event if any threshold is violated
            if reasons_for_dos_detection:
                reason_string = "; ".join(reasons_for_dos_detection)
                mac_address = interface_info.get(interface, {}).get('mac', '')
                ip_address = interface_info.get(interface, {}).get('ip', '')

                log_event(
                    component=1,  # Assuming 1 represents this component
                    resource='System stats',
                    log_text = f"Potential DoS detected on {interface}. Reason: {reason_string}",
                    event_reason=reason_string,
                    mac_address=mac_address,
                    ip_address=ip_address,
                    event_type=DistributedDOSEvents,
                    event_subtype=DDoSAttackDetected,
                )                
                
        previous_stats = copy.deepcopy(current_stats)
        time.sleep(TIME_RANGE)

# MONITOR PORT SCAN
def PORT_SCAN(file_path='/var/log/ufw.log'):
    print("PS")

    global PORT_SCAN_last_cleanup_time  # Use the global variable to track cleanup time

    try:
        with open(file_path, 'r') as file:
            file.seek(0, 2)  # Move to the end

            while True:
                line = file.readline()
                if line:
                    match = re.search(port_scan_pattern, line)
                    if match:
                        timestamp_str = match.group(1)  # Extract timestamp
                        ufw_action = match.group(2)  # Extract UFW action
                        src_ip_address = match.group(3)  # Extract source IP address
                        dst_ip_address = match.group(4)  # Extract destination IP address

                        current_date = datetime.fromisoformat(timestamp_str)
                        
                        # Count connection attempts for simple port scanning detection
                        if ufw_action == "BLOCK":
                            port_scan_connection_attempts[src_ip_address].append(current_date)

                            while port_scan_connection_attempts[src_ip_address] and \
                                    (current_date - port_scan_connection_attempts[src_ip_address][0]) > TIME_WINDOW_FOR_PORT_SCAN:
                                port_scan_connection_attempts[src_ip_address].popleft()

                            total_attempts = len(port_scan_connection_attempts[src_ip_address])

                            if total_attempts >= PORT_SCAN_THRES:
                                # Check if we are in cooldown period for this IP address
                                if (src_ip_address not in PORT_SCAN_last_alert_time) or \
                                   ((current_date - PORT_SCAN_last_alert_time[src_ip_address]) > PORT_SCAN_ALERT_TIMEOUT):
                                    
                                    # send_udp_packet(structured_data)
                                    log_event(
                                        component=1,  # Assuming 1 represents this component
                                        resource='ufw.log',
                                        log_text=f"Alert: {ufw_action} from {src_ip_address} to {dst_ip_address}",
                                        event_reason='Potential port scan detected',
                                        mac_address=get_mac_address(),
                                        ip_address=dst_ip_address,
                                        event_type=NetworkActivityEvents,
                                        event_subtype=OpenPortScans,
                                    )


                                    PORT_SCAN_last_alert_time[src_ip_address] = current_date  # Update last alert time
                                
                                del port_scan_connection_attempts[src_ip_address] # reset the counter after one report

                else:
                    time.sleep(0.1)  

                if datetime.now() - PORT_SCAN_last_cleanup_time >= timedelta(minutes=1):
                    device_ip = get_device_ip()
                    device_mac = get_mac_address()
                    for blocked_ip in port_scan_connection_attempts:
                        # print("date: ",datetime.now()," abc: ",PORT_SCAN_last_alert_time[blocked_ip])
                        if (datetime.now(timezone.utc)-PORT_SCAN_last_alert_time.get(blocked_ip))>PORT_SCAN_ALERT_TIMEOUT: 
                            log_event(
                                component=1,  # Assuming 1 represents this component
                                resource='ufw.log',
                                log_text=f"Alert: BLOCK from {blocked_ip} to {device_ip}",
                                event_reason='BLOCK connection detected.',
                                mac_address=device_mac,
                                ip_address=device_ip,
                                event_type=NetworkActivityEvents,
                                event_subtype=BlockedConnection,
                            )
                        
                    port_scan_connection_attempts.clear()  # Clear all stored connection attempts
                    PORT_SCAN_last_cleanup_time = datetime.now()  # Update last cleanup time

    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return



# Function to extract USB device information using lsusb
def get_usb_device_info(id_vendor, id_product):
    try:
        # Run lsusb command to get detailed information about USB devices
        result = subprocess.run(['lsusb', '-v'], capture_output=True, text=True, check=True)
        
        # Find the device with matching idVendor and idProduct
        device_info = {}
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if f"idVendor {id_vendor}" in line and f"idProduct {id_product}" in line:
                # Extract relevant information from subsequent lines
                for j in range(i + 1, len(lines)):
                    if lines[j].strip().startswith('iManufacturer'):
                        device_info['manufacturer'] = lines[j].split()[-1]
                    elif lines[j].strip().startswith('iProduct'):
                        device_info['product'] = lines[j].split()[-1]
                    elif lines[j].strip().startswith('iSerial'):
                        device_info['serial_number'] = lines[j].split()[-1]
                    elif lines[j].strip().startswith('Bus'):
                        bus_match = re.search(r'Bus (\d+)', lines[j])
                        device_info['bus'] = bus_match.group(1) if bus_match else ''
                        device_match = re.search(r'Device (\d+):', lines[j])
                        device_info['device_num'] = device_match.group(1) if device_match else ''
                    elif lines[j].strip().startswith('Device Descriptor:'):
                        break  # Stop parsing when a new device descriptor is encountered

        return device_info
    except subprocess.CalledProcessError as e:
        print(f"Error running lsusb command: {e}")
        return {}


def process_usb_event(timestamp_str, event_description):
    current_time = datetime.fromisoformat(timestamp_str)

    # Determine event sub-type based on the description
    if "new" in event_description.lower() and "device number" in event_description.lower():
        event_sub_type = DeviceConnection
        event_reason = "USB device connected"
    elif "disconnect" in event_description.lower():
        event_sub_type = DeviceConnection
        event_reason = "USB device disconnected"
    else:
        # Handle cases where the event is neither connect nor disconnect
        return

    # Extract relevant information from the event description (add more fields as needed)
    # Example: Extracting idVendor and idProduct
    id_vendor_match = re.search(r"idVendor=(\w+)", event_description)
    id_product_match = re.search(r"idProduct=(\w+)", event_description)

    id_vendor = id_vendor_match.group(1) if id_vendor_match else ""
    id_product = id_product_match.group(1) if id_product_match else ""
    
    # Get additional USB device information using lsusb
    usb_device_info = get_usb_device_info(id_vendor, id_product)
    
    
    log_event(
        component=1,
        resource=usb_device_info.get('product', 'syslog'),  # Use product name from lsusb if available
        log_text=event_description,
        event_reason=event_reason,
        mac_address=get_mac_address(),
        ip_address=get_device_ip(),
        event_type=EndpointSecurityEvents,
        event_subtype=event_sub_type        
    )

# MONITOR USB EVENTS
def USB_EVENT(file_path='/var/log/syslog'):
    print("USB")
    
    MTP_PROBE_DELAY = 0.5  # Wait for 0.5 seconds after mtp-probe lines

    try:
        with open(file_path, 'r') as file:
            file.seek(0, 2)  # Move to the end of the file

            while True:
                line = file.readline()
                if line:
                    if "usb" in line.lower():  # Filter lines related to USB events
                        # print(line)
                        # Check for mtp-probe line and wait if found
                        if "mtp-probe" in line:
                            time.sleep(MTP_PROBE_DELAY)
                            continue

                        match = USB_event_pattern.search(line)
                        if match:
                            # print("Match found")  # Indicate a match
                            # print("Match groups:", match.groups())
                            timestamp_str = match.group(1)
                            event_description = match.group(2)
                            process_usb_event(timestamp_str, event_description)
                else:
                    time.sleep(0.1)  # Sleep briefly if no new lines

    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return



def get_interface_ip(interface):
    """
    Gets the IPv4 address of the specified network interface (e.g., 'eno1' or 'wlan0').
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface.encode('utf-8')[:15])
        )[20:24])
        return ip_addr
    except Exception as e:
        logging.error(f"Error getting IP for interface {interface}: {e}")
        return None

def get_interface_mac(interface):
    """
    Gets the MAC address of the specified network interface by reading sysfs.
    """
    try:
        with open(f'/sys/class/net/{interface}/address') as f:
            mac_address = f.readline().strip()
            return mac_address
    except Exception as e:
        logging.error(f"Error getting MAC for interface {interface}: {e}")
        return None


def extract_log_message(log_line):
    """
    Extracts the message portion from a syslog-style log line.
    For example, given a log line like:
      "Jan 21 10:15:34 mypc gdm-session-worker[1234]: pam_unix(gdm-password:session): session opened for user username(uid=1000) by (uid=0)"
    it returns:
      "session opened for user username(uid=1000) by (uid=0)"
    
    This function looks for the first occurrence of "]: " and returns the text after it.
    If not found, it falls back to splitting on the first colon.
    """
    if "]: " in log_line:
        parts = log_line.split("]: ", 1)
        return parts[1].strip()
    elif ": " in log_line:
        parts = log_line.split(": ", 1)
        return parts[1].strip()
    else:
        return log_line.strip()

def tail_f(filename):
    """
    Generator that yields only new lines appended to the file.
    It seeks to the file's end once and then yields new data.
    """
    try:
        with open(filename, 'r') as f:
            f.seek(0, os.SEEK_END)  # Skip existing content
            while True:
                line = f.readline()
                if line:
                    yield line.strip()
                else:
                    time.sleep(0.1)
                    yield None
    except Exception as e:
        logging.error(f"Error tailing file {filename}: {e}")
        time.sleep(5)
        yield None


def SOFTWARE_EVENTS():
    print("SOFTWARE EVENTS")
    device_ip=get_device_ip()
    device_mac = get_mac_address()

    if not device_ip or not device_mac:
        print("Could not determine an active interface with IP and MAC. Exiting.")
        exit()

    # Create tail generators for each log file
    log_files = [DPKG_LOG, APT_HISTORY_LOG, AUTH_LOG]
    tails = {lf: tail_f(lf) for lf in log_files}

    # Precompile regex patterns for each log file type
    dpkg_pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(?P<action>install|remove) '
        r'(?P<package>[\S]+) '
        r'(?P<version>[\S]+) <none>'
    )
    apt_pattern = re.compile(r'Commandline: apt (install|remove) (?P<package>[\S]+)')
    sudo_pattern = re.compile(r'COMMAND=/usr/bin/apt (install|remove) (?P<package>[\S]+)')


    while True:
        for lf, gen in tails.items():
            try:
                line = next(gen)
            except Exception as e:
                logging.error(f"Error getting line from {lf}: {e}")
                continue

            if not line:
                continue

            if lf == DPKG_LOG:
                match = dpkg_pattern.search(line)
                if match:
                    log_event(1, match.group('package'), line, match.group('action'), device_ip, device_mac,UserActivityEvents,UnauthorisedSoftwareInstallation if 'install' in match.group('action').lower() else UnauthorisedSoftwareRemoval)
            elif lf == APT_HISTORY_LOG:
                match = apt_pattern.search(line)
                if match:
                    log_event(1, match.group('package'), line, match.group(1), device_ip, device_mac,UserActivityEvents,UnauthorisedSoftwareInstallation if 'install' in match.group(1).lower() else UnauthorisedSoftwareRemoval)
            elif lf == AUTH_LOG:
                match = sudo_pattern.search(line)
                if match:
                    log_event(1, match.group('package'), line, f"Unauthorized {match.group(1)}", device_ip, device_mac,UserActivityEvents,UnauthorisedSoftwareInstallation if 'install' in  f"Unauthorized {match.group(1)}".lower() else UnauthorisedSoftwareRemoval)
        time.sleep(0.1)





USER_ACTIVITY_SUBTYPE_MAPPING = {
    "User Addition": UserCreation,
    "User Deletion": UserDeletion,
    "Password Change": PasswordChange,
    "Sudo Command": PrivilegeEscalation,
    "Policy Violation": PolicyViolations,
    "Successful Login": SuccessfulLogin,
    "Failed Login": FailedLogin,
    "Logout": Logout,
    "IdleSessions": IdleSessions,
    "UnusualUserActivity": UnusualUserActivity,
    "Generic": 0  # Default
}


def map_subtype(subtype_str):
    return USER_ACTIVITY_SUBTYPE_MAPPING.get(subtype_str, 0)


def remove_ansi_codes(text):
    """Removes ANSI escape sequences from a string."""
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def determine_user_event_subtype(message, resource, login_hour=None):
    """Determines the user event subtype."""
    msg = remove_ansi_codes(message).lower()

    # Check for odd-hour login *first*
    if login_hour is not None and (UNUSUAL_START_HOUR <= login_hour or login_hour < UNUSUAL_END_HOUR):
        return "UnusualUserActivity"  #  Odd-hour is a type of Unusual Activity

    # Check for creation keywords:
    if "new user" in msg or "adduser" in msg or "useradd" in msg:
        return "UserCreation"
    # Check for deletion keywords:
    if re.search(r"delete\s*'?user", msg) or "userdel" in msg or "removed" in msg:
        return "UserDeletion"
    # Check for policy violation keywords:
    if "failure" in msg or "permission denied" in msg or "not in sudoers" in msg or "failed password" in msg or "incorrect password" in msg:
        return "PolicyViolations"
    # Check for idle session keywords:
    if "idle" in msg or "session timed out" in msg:
        return "IdleSessions"

    # If none of the above, it's some other kind of unusual activity or generic event.
    return "UnusualUserActivity"


def extract_generic_event_reason(message, resource, login_hour=None):
    """
    Extracts the event reason, including "ODD HOUR LOGIN DETECT".
    """
    clean_message = remove_ansi_codes(message)

    # Check for odd-hour login *first*
    if login_hour is not None and (UNUSUAL_START_HOUR <= login_hour or login_hour < UNUSUAL_END_HOUR):
        return "ODD HOUR LOGIN DETECT"

    KEY_TOKENS = {
        "pam_unix": "pam_unix",
        "session opened": "session opened",
        "session closed": "session closed",
        "new user": "new user",
        "delete user": "delete user",
        "group added": "group added",
        "group deleted": "group deleted",
        "password changed": "password changed",
        "sudo": "sudo",
        "failed password": "failed password",
        "incorrect password": "incorrect password"
    }
    for token, reason in KEY_TOKENS.items():
        if token in clean_message.lower():
            return reason

    paren_match = re.search(r"\([^)]*:[^)]*\)", clean_message)
    if paren_match:
        return paren_match.group(0).strip()

    known_resources = {"userdel", "useradd", "passwd", "groupadd", "groupdel"}
    if resource.lower() in known_resources:
        return resource

    words = clean_message.split()
    if words and words[0] in ["delete", "remove", "add", "new", "changed"]:
        return " ".join(words[:2])

    if ":" in clean_message:
        left_part = clean_message.split(":", 1)[0].strip()
        if len(left_part) < 50:
            return left_part

    return ""

def parse_single_log_entry(log_entry, device_ip, device_mac):
    """Parses a single log entry and returns a structured dictionary."""
    timestamp_regex = r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\+\-]\d{2}:\d{2})"
    username_regex = r"(?P<username>[\w-]+)"
    component_regex = r"(?P<component>\S+?)(?:\[(?P<pid>\d+)\])?"
    message_regex = r"(?P<message>.*)"
    combined_regex = rf"{timestamp_regex}\s+{username_regex}\s+{component_regex}:\s+{message_regex}"
    match = re.match(combined_regex, log_entry)
    if not match:
        logging.warning(f"Failed to parse log line: {log_entry}")
        return None

    timestamp_str = match.group("timestamp")
    username = match.group("username")
    component = match.group("component")
    pid = match.group("pid") if match.group("pid") else "0"
    message = match.group("message")

    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        logging.warning(f"Failed to parse timestamp: {timestamp_str}")
        return None

    event_type_str = "User Activity Event"
    event_sub_type_str = "Generic"
    resource = component
    
    event_reason = extract_generic_event_reason(message, resource)
    login_hour = None
    if "session opened" in message.lower():
        login_hour = timestamp.hour

    event_reason = extract_generic_event_reason(message, resource, login_hour)
    event_sub_type_str = determine_user_event_subtype(message, resource, login_hour)

    event_patterns = {
        "useradd": r"new user: name=(?P<user>\w+)",
        "userdel": r"delete user '(?P<user>\w+)'",
        "passwd_change": r"password changed for (?P<user>\w+)",
        "sudo_command": r"sudo:\s+(?P<sudo_user>\w+)\s+:\s+.*;\s+COMMAND=(?P<command>.+)",
        "sudo_fail": r"sudo:\s+(?P<user>\w+)\s+:\s+user NOT in sudoers",
        "sshd_accepted": r"Accepted password for (?P<user>\w+)",
        "sshd_failed": r"Failed password for (?:invalid user )?(?P<user>\w+)",
        "sshd_disconnect": r"Disconnected from user (?P<user>\w+)"
    }

    for event_name, event_regex in event_patterns.items():
        event_match = re.search(event_regex, message)
        if event_match:
            if event_name == "useradd":
                event_sub_type_str = "User Addition"
                username = event_match.group("user")
            elif event_name == "userdel":
                event_sub_type_str = "User Deletion"
                username = event_match.group("user")
            elif event_name == "passwd_change":
                event_sub_type_str = "Password Change"
                username = event_match.group("user")
            elif event_name == "sudo_command":
                event_sub_type_str = "Sudo Command"
                username = event_match.group("sudo_user")
                resource = event_match.group("command")
            elif event_name == "sudo_fail":
                event_sub_type_str = "Policy Violation"
                username = event_match.group("user")
                event_reason = "user NOT in sudoers"
            elif event_name == "sshd_accepted":
                event_sub_type_str = "Successful Login"
                username = event_match.group("user")
            elif event_name == "sshd_failed":
                event_sub_type_str = "Failed Login"
                username = event_match.group("user")
                event_reason = "Failed password"
            elif event_name == "sshd_disconnect":
                event_sub_type_str = "Logout"
                username = event_match.group("user")
            break

    event_data = {
        "event_id": None,
        "date": int(timestamp.day),
        "month": int(timestamp.month),
        "year": int(timestamp.year),
        "hh": int(timestamp.hour),
        "mm": int(timestamp.minute),
        "ss": int(timestamp.second),
        "event_type": UserActivityEvents,
        "event_sub_type": map_subtype(event_sub_type_str),
        "component": 1,
        "user": username,
        "resource": resource,
        "log_text": message,
        "event_reason": event_reason,
        "pid": int(pid),
        "device_type": PC, 
        "device_macId": device_mac,
        "device_ip": device_ip
    }
    return event_data

# ----------------------- Tail Utility Function -----------------------
def tail_f(filename, encoding="utf-8"):
    """
    Generator that yields new lines appended to the file.
    """
    try:
        file = open(filename, 'r', encoding=encoding)  # Open file outside the loop
        file.seek(0, os.SEEK_END)  # Seek to the end initially
        while True:
            line = file.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.2)

    except Exception as e:
        logging.error(f"Error tailing file {filename}: {e}")


def USER_ACTIVITY_EVENTS():
    device_ip = get_device_ip()
    device_mac = get_mac_address()
    if not device_ip or not device_mac:
        print("Could not determine device IP or MAC. Exiting.")
        exit()

    log_files = [
        "/var/log/auth.log",
        "/var/log/syslog"
    ]

    tails = {lf: tail_f(lf) for lf in log_files}

    event_id_counter = 1
    print("USER ACTIVITY EVENTS")

    while True:
        for lf, generator in tails.items():
            # print('hi')
            try:
                # print(generator)

                for line in generator:  # Iterate directly through the generator
                    # print('hi4')
                    if line:
                        parsed_event = parse_single_log_entry(line, device_ip, device_mac)
                        if parsed_event:
                            parsed_event["event_id"] = event_id_counter
                            event_id_counter += 1
                            
                            send_udp_packet(parsed_event)
                            logging.info(parsed_event)
                            time.sleep(TIME_RANGE)
                    # else:
                    #     print('no line dude')

                # Generator exhausted (e.g., due to file rotation or error)
                logging.warning(f"Generator for {lf} exhausted. Restarting.")
                tails[lf] = tail_f(lf)  # Restart the generator

            except Exception as e:
                logging.error(f"Error processing {lf}: {e}")
                # Consider restarting the generator or exiting, depending on the error
                tails[lf] = tail_f(lf) #restart the generator
                continue



# Process specific authentication events
def process_auth_event(timestamp_str, process, pid, log_text):
    current_time = datetime.fromisoformat(timestamp_str)
    event_type = AuthenticationEvents
    event_sub_type = 0
    event_reason = 0

    user = getpass.getuser()

    # Checking for specific authentication events
    if "authentication failure" in log_text:
        event_sub_type = FailedLogin
        event_reason = "Authentication failure"
        user_match = re.search(r"user=(\S+)", log_text)
        if user_match:
            user = user_match.group(1)

    elif "user NOT in sudoers" in log_text:
        event_sub_type = PrivilegeEscalation
        event_reason = "User not in sudoers"

    elif "Invalid verification code" in log_text:
        event_sub_type = InvalidverificationCode
        event_reason = "Invalid verification code"

    elif "Accepted password for" in log_text:
        event_sub_type = SuccessfulLogin
        event_reason = "Successful login"

    elif "Failed password for" in log_text:
        event_sub_type = FailedLogin
        event_reason = "Failed login attempt"

    elif "Connection closed by" in log_text:
        event_sub_type = Logout 
        event_reason = "User connection closed"
    
    elif "Gnupg" in log_text:
        event_sub_type = FileEncryption
        event_reason = "file encrypted"
    
    elif "password change" in log_text:
        event_sub_type = PasswordChange
        event_reason = "password change"

    else:
        return  # Ignore unrecognized logs
    
    log_event(component=1,resource=process,log_text=log_text,event_reason=event_reason,mac_address=get_mac_address(),ip=get_device_ip(),event_type=event_type,event_subtype=event_sub_type)

    # structured_data = {
    #     'event_id': generate_event_id(),
    #     'date': current_time.day,
    #     'month': current_time.month,
    #     'year': current_time.year,
    #     'hh': current_time.hour,
    #     'mm': current_time.minute,
    #     'ss': current_time.second,
    #     'event_type': event_type,  # Now a string
    #     'event_sub_type': event_sub_type,  # Now a string
    #     'component': 1,
    #     'user': user,
    #     'resource': process,
    #     'log_text': log_text,
    #     'event_reason': event_reason,
    #     'pid': int(pid),
    #     'device_type': PC,
    #     'device_macId': get_mac_address(),
    #     'device_ip': get_device_ip(),
    # }

    # # Send via UDP
    # send_udp_packet(structured_data)

# Monitor logs continuously
def AUTH_monitor(file_paths):
    print("Monitoring authentication logs...")

    files = {}
    for file_path in file_paths:
        try:
            file = open(file_path, 'r')
            file.seek(0, 2)  # Move to end of file
            files[file_path] = file
        except FileNotFoundError:
            print(f"Error: Log file '{file_path}' not found.")

    while True:
        for file_path, file in files.items():
            line = file.readline()
            if line:
                match = auth_event_pattern.search(line)
                if match:
                    process_auth_event(
                        match.group("timestamp"),
                        match.group("process"),
                        match.group("pid"),
                        match.group("log_text")
                    )
            else:
                time.sleep(0.1)  # Avoid CPU overload



# PARSE CLAMAV LOGS
def parse_clamav_output(scan_output):
    """Parse ClamAV scan results and send findings via UDP."""
    try:
        for line in scan_output.split('\n'):
            match = re.match(r'^(.*?): (.*)', line.strip())
            if match and "FOUND" in match.group(2):
                log_text = f"File: {match.group(1)}, Result: {match.group(2)}"
                log_event(
                    component=1,
                    resource='clamav',
                    log_text=log_text,
                    event_reason='Detected Virus',
                    mac_address=get_mac_address(),
                    ip_address=get_device_ip(),
                    event_type=EndpointSecurityEvents,
                    event_subtype=MalwareDetection                    
                )
    except Exception as e:
        logging.error(f"Error processing ClamAV scan output: {e}")


# SCAN the given directory for malware.
def scan_directory(directory_path=f'/home/{getpass.getuser()}/Downloads'):
    """Scans a directory with ClamAV and processes the output."""
    try:
        if os.path.isdir(directory_path):
            result = subprocess.run(["clamscan", "-r", directory_path], capture_output=True, text=True)
            parse_clamav_output(result.stdout)
        else:
            logging.error(f"Invalid directory path: {directory_path}")
    except Exception as e:
        logging.error(f"Error occurred during scan: {str(e)}")


# Schedule scanning for given/default(downlods folder of current user) directory.
def SCHEDULE_SCAN_FOR_MALWARE(interval=600):
    print('SCHEDULE_SCAN_FOR_MALWARE')
    """Schedules directory scanning every 'interval' seconds."""
    while True:
        scan_directory()
        # logging.info(f"Next scan in {interval // 60} minutes...")
        time.sleep(interval)


# Auto scan for malware by mounting that device.
def scan_usb(device_path):
    """Mount and scan a USB device."""
    try:
        os.makedirs(USB_MOUNT_PATH, exist_ok=True)
        subprocess.run(["mount", device_path, USB_MOUNT_PATH], check=True)
        scan_directory(USB_MOUNT_PATH)
        subprocess.run(["umount", USB_MOUNT_PATH], check=True)
    except Exception as e:
        logging.error(f"Error scanning USB: {str(e)}")

# Detetc new storage device insertion and calls scan_usb().
def MONITOR_USB_MALWARE():
    """Monitor for USB device connections and scan them automatically."""
    print("MONITOR_USB_MALWARE")
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block')
    
    # logging.info("USB monitor started...")
    
    for device in iter(monitor.poll, None):
        if device.action == "add" and "ID_FS_TYPE" in device.properties:
            device_path = f"/dev/{device.device_node.split('/')[-1]}"
            # logging.info(f"USB Detected: {device_path}")
            scan_usb(device_path)




def get_syscall_name(syscall_number):
    """Maps a syscall number to its name (best effort)."""
    syscalls = {
        0: "read",
        1: "write",
        2: "open",
        3: "close",
        4: "stat",
        5: "fstat",
        8: "lstat",
        9: "mmap",
        10: "mprotect",
        11: "munmap",
        21: "access",
        59: "execve",
        83: "mkdir",
        84: "rmdir",
        85: "creat",
        87: "unlink",
        89: "readlink",
        90: "chmod",
        91: "fchmod",
        92: "chown",
        93: "fchown",
        94: "lchown",
        262: "statx",  # Newer, more detailed stat
        56: "openat"   # Added mapping for syscall 56 if needed.
    }
    return syscalls.get(syscall_number, f"Unknown syscall ({syscall_number})")


def parse_audit_line(line):
    """Parses a single auditd log line into a dictionary."""
    data = {}
    # Split the line into key=value pairs.
    for item in line.split():
        if '=' in item:
            key, value = item.split('=', 1)
            # Remove quotes from the value, if present.
            value = value.strip('"')
            data[key] = value
    return data


def normalize_event(current_event):
    # Extract and normalize timestamp and event id.
    try:
        # e.g. msg might be "audit(1681234567.123:123): ..."
        msg_field = current_event.get('msg', '')
        parts = msg_field.split('audit(')[1].split(':')
    except Exception as e:
        logging.error(f'Error: {e}')

    # Normalize syscall.
    raw_syscall = current_event.get('syscall', '')
    if raw_syscall.startswith("Unknown syscall"):
        m = re.search(r'\((\d+)\)', raw_syscall)
        if m:
            syscall_num = int(m.group(1))
            normalized_syscall = get_syscall_name(syscall_num)
        else:
            normalized_syscall = raw_syscall
    else:
        try:
            normalized_syscall = get_syscall_name(int(raw_syscall))
        except Exception:
            normalized_syscall = raw_syscall

    # Decode proctitle.
    raw_proctitle = current_event.get('proctitle', '')
    decoded_proctitle = ""
    file_from_proctitle = ""
    if raw_proctitle:
        try:
            decoded_proctitle = bytes.fromhex(raw_proctitle).decode('utf-8', errors='ignore')
            # If there is a null character, assume the part after it is a file name.
            if "\x00" in decoded_proctitle:
                parts = decoded_proctitle.split("\x00")
                if len(parts) > 1:
                    file_from_proctitle = parts[1]
        except Exception:
            decoded_proctitle = raw_proctitle

    # Normalize file path.
    file_path = current_event.get('name', '')
    # Check if file_path appears to have a file extension.
    _, ext = os.path.splitext(file_path)
    if not ext and file_from_proctitle:
        # Assume file_path is a directory; append the file name extracted from proctitle.
        file_path = os.path.join(file_path, file_from_proctitle)

    # Determine event_type (fixed) and event_subtype (based on the comm field).
    fixed_event_type = "file and object modification"
    comm = current_event.get('comm', '').lower()
    if comm == "nano":
        event_subtype = FileModification
    elif comm == "touch":
        event_subtype = FileCreation
    elif comm == "rm":
        event_subtype = FileDeletion
    elif comm == "cat":
        event_subtype = FileRead
    else:
        event_subtype = 0
        
    log_text = f"{file_path}, exe: {current_event.get('exe')}, {normalized_syscall} success: {current_event.get('success')}"
    print(log_text)
    #event_reason = f'{current_event.get('exe')}'
    log_event(
        component=1,
        resource='auditd',
        log_text=log_text,
        event_reason='dfdf',
        mac_address=get_mac_address(),
        ip_address=get_device_ip(),
        event_type=FileAndObjectAccessEvents,
        event_subtype=event_subtype        
    )



def MONITOR_FILE_CREATION():
    print('MONITOR_FILE_CREATION')
    log_file = '/var/log/audit/audit.log' 
    monitored_directory = f'/home/{getpass.getuser()}/Downloads'

    # Open the audit log file.
    try:
        f = open(log_file, 'r')
    except FileNotFoundError:
        logging.error(f"Error: Log file not found: {log_file}")
        exit(1)
    except Exception as e:
        logging.error(f"An error occurred opening the file: {e}")
        exit(1)

    # Seek to the end of the audit log file so we only process new lines.
    f.seek(0, os.SEEK_END)

    current_event = {}  # Accumulates lines belonging to a single event.

    while True:
        line = f.readline()
        if not line:
            # No new line available, wait briefly and try again.
            time.sleep(1)
            continue

        line_data = parse_audit_line(line)
        if not line_data.get('type'):
            continue  # Skip lines without a type field.

        # A new 'msg' field indicates the start of a new event.
        if 'msg' in line_data:
            if current_event and (line_data['msg'] != current_event.get('msg')):
                # Process the completed event only if its file path includes the monitored directory.
                if 'name' in current_event and monitored_directory in current_event['name']:
                    try:
                        normalize_event(current_event)
                    except Exception:

                        pass
                # Reset the event accumulator for the new event.
                current_event = {}
            current_event['msg'] = line_data['msg']

        # Merge data into current_event based on the type field.
        if line_data['type'] == 'SYSCALL':
            current_event.update(line_data)
        elif line_data['type'] == 'PATH':
            if 'name' in line_data and monitored_directory in line_data['name']:
                current_event.update(line_data)
        elif line_data['type'] == 'CWD':
            current_event.update(line_data)
        elif line_data['type'] == 'PROCTITLE':
            current_event.update(line_data)








































# Global list to store processes
processes = []

def signal_handler(sig, frame):
    """Handles Ctrl+C signal to stop all processes."""
    for p in processes:
        if p.is_alive():
            print(f'{p.name} terminated')
            p.terminate()  # Forcefully terminate the process
            p.join()       # Wait for process to terminate

    sys.exit(0)  # Exit the program

if __name__ == '__main__':
    # Handle Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Define process configurations (replace with your actual functions)
    process_configs = [
        (HVDT, ()),
        (PORT_SCAN, ('/var/log/ufw.log',)),
        (DOS, ()), # some bug in this code. (resolved)
        (USB_EVENT,()),
        (AUTH_monitor,([AUTH_LOG_FILES_PATH])),
        (SOFTWARE_EVENTS,()),
        (USER_ACTIVITY_EVENTS,()),
        (MONITOR_USB_MALWARE,()),
        (SCHEDULE_SCAN_FOR_MALWARE,()),
        (MONITOR_FILE_CREATION,())
        
        
    ]

    # Create and start processes
    for func, args in process_configs:
        process = Process(target=func, args=args, name=func.__name__)  # Setting the name of the process
        processes.append(process)
        process.start()

    try:
        while True:
            time.sleep(1)  # Main thread just sleeps and waits for signal
    except KeyboardInterrupt:
        print('Exception raised.')
        pass
