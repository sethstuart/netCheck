import os
import re
import subprocess
import threading
import time
import http.server
import socketserver
from http import HTTPStatus
from requests import get

# Environment variables (set these in your Dockerfile)
POD_NETWORK_RANGE = os.getenv('POD_NETWORK_RANGE', '10.244.0.0/16')
NAMESPACE = os.getenv('NAMESPACE', 'default')
NETCHECK_SVC_NAME = os.getenv('NETCHECK_SVC_NAME', 'netCheck')

PORT = 8080
HOSTNAME = "0.0.0.0"  # Listen on all interfaces

own_ip = None

# Define a simple HTTP request handler
class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/checker':
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            # Concatenate 'OK' with the IP address and encode it as bytes
            response_message = f"OK - IP: {own_ip}".encode()
            self.wfile.write(response_message)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

# Function to start the HTTP server
def start_server():
    with socketserver.TCPServer((HOSTNAME, PORT), SimpleHTTPRequestHandler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()

# Function to run commands and log the output
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True)
        log_output(command, result.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        log_output(command, e.output.decode('utf-8'), error=True)

# Function to log the output
def log_output(command, output, error=False):
    log_message = f"Command: {command}\nOutput:\n{output}\n"
    if error:
        log_message = f"Error running {command}\nOutput:\n{output}\n"
    print(log_message)

def self_identification():
    global netcheckers_info, own_ip  # Declare as global to modify the global own_ip variable

    # Get all IP addresses
    ip_output = subprocess.check_output("ip a", shell=True).decode()
    log_output("IP Address Output", ip_output)  # Log the output of 'ip a'
    
    # Determine the subnet size from POD_NETWORK_RANGE (assuming it's in CIDR notation like '192.168.0.0/16')
    try:
        subnet_base, subnet_size = POD_NETWORK_RANGE.split('/')
        subnet_size = int(subnet_size)
    except ValueError:
        log_output("Subnet Parsing", "Invalid POD_NETWORK_RANGE format. Ensure it's in CIDR notation like '192.168.0.0/16'.", error=True)
        return
    
    # Adjust the number of octets to match based on subnet size
    if subnet_size <= 8:
        num_octets = 1
    elif subnet_size <= 16:
        num_octets = 2
    elif subnet_size <= 24:
        num_octets = 3
    else:
        num_octets = 4  # For subnets /24 and larger, match all four octets
    
    subnet_pattern = r'\.'.join(subnet_base.split('.')[:num_octets]) + (r'\.\d{1,3}' * (4 - num_octets))
    log_output("Subnet Pattern", subnet_pattern)  # Log the expected subnet pattern
    
    # Define a regex pattern to match the IP addresses in the specified range
    cidr_regex = re.compile(subnet_pattern)
    
    # Find all matches for the IP address in the specified range
    ip_matches = cidr_regex.findall(ip_output)
    log_output("IP Matches", str(ip_matches))  # Log the results of the regex matching
    
    # If matches found, assume the first match is the pod's own IP (this may need adjustment based on your network setup)
    if ip_matches:
        own_ip = ip_matches[0]
        log_output("Own IP Identified", own_ip)  # Log the identified own IP
    else:
        log_output("Self Identification", f"Failed to identify the pod's own IP address in the specified range: {POD_NETWORK_RANGE}", error=True)
        # Pause indefinitely for log checking
        while True:
            time.sleep(3600)
    
    # Get all ARP table info
    arp_output = subprocess.check_output("arp -a", shell=True).decode()
    log_output("ARP Table Output", arp_output)  # Log the output of 'arp -a'    
    netcheckers_info = [{'ip': own_ip, 'arp': 'arp_info', 'svc_name': NETCHECK_SVC_NAME, 'mac': 'mac_address'}]

    # Log the information
    log_info = f"** Pod Info: {own_ip} (this pod) **\n"
    for info in netcheckers_info:
        log_info += f"IP: {info['ip']}, ARP: {info['arp']}, SVC Name: {info['svc_name']}, MAC: {info['mac']}\n"
    log_output("Self Identification/ARP Table Check", log_info)

def dns_resolution():
    for info in netcheckers_info:
        if info['ip'] != own_ip:  # Skip own IP
            # nslookup
            run_command(f"nslookup {info['ip']}")
            # dig
            run_command(f"dig {info['svc_name']}")

def ping_test():
    for info in netcheckers_info:
        if info['ip'] != own_ip:  # Skip own IP
            run_command(f"ping -c 5 {info['ip']}")

def api_endpoint_test():
    for info in netcheckers_info:
        log_output(f"For {info}",f" in {netcheckers_info}")
        if info['ip'] != own_ip:  # Skip own IP
            for _ in range(5):  # Repeat 5 times
                response = get(f"http://{info['ip']}:8080/api/checker")
                log_output(f"API Endpoint Test to {info['ip']}", f"Status Code: {response.status_code}")

def netstat():
    run_command("netstat -tuln")

def netcat_test():
    # Placeholder for netcat test commands
    pass

if __name__ == "__main__":
    # Start the HTTP server in a new thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Perform self identification and ARP table check
    self_identification()

    # Run other network tests
    dns_resolution()
    ping_test()
    api_endpoint_test()
    netstat()
    netcat_test()

    # Keep the script running to keep the server alive
    server_thread.join()
