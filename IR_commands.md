# Incident Response: Web Server Isolation and Attacker Eviction
## Attack Analysis Summary

The attacker:
1. Uploaded a reverse shell (`reverse6.php`) to `/var/www/secureskies/secureskies/uploads/`
2. Established a reverse shell connection from web server to attacker IP `12.0.0.45:4444`
3. Downloaded malicious scripts: `send_db.py`, `nc_upload_share.py`, `mail_test.py`, `dphelper_v2.4_test_build`
4. Exfiltrated database via `send_db.py`
5. Uploaded files to Nextcloud and sent phishing emails
6. Downloaded nmap to `/tmp/nmap_transfer/` for network reconnaissance

---

## Incident Response Commands

### **1. On Security Onion - Immediate Network Isolation**

```bash
# Block attacker IP at the network level
sudo iptables -I FORWARD 1 -s 12.0.0.45 -j DROP
sudo iptables -I FORWARD 1 -d 12.0.0.45 -j DROP
sudo iptables -I INPUT 1 -s 12.0.0.45 -j DROP
sudo iptables -I OUTPUT 1 -d 12.0.0.45 -j DROP

# Save iptables rules
sudo iptables-save > /tmp/ir_iptables_backup.rules
```

### **2. On VyOS Router - Block Attacker at Perimeter**

```bash
# Enter configuration mode
configure

# Block attacker IP completely
#name can be WAN_TO_LAN or any other
set firewall name WAN_TO_LAN rule 1 action drop
set firewall name WAN_TO_LAN rule 1 source address 12.0.0.45
set firewall name WAN_TO_LAN rule 1 description "IR: Block attacker 12.0.0.45"

set firewall name LAN_TO_WAN rule 1 action drop
set firewall name LAN_TO_WAN rule 1 destination address 12.0.0.45
set firewall name LAN_TO_WAN rule 1 description "IR: Block outbound to attacker"

# Commit and save
commit
save

# Exit configuration
exit
```

### **3. On Ubuntu Web Server (secureskies) - Kill Active Connections**

```bash
# Add local firewall rules
sudo iptables -I INPUT 1 -s 12.0.0.45 -j DROP
sudo iptables -I OUTPUT 1 -d 12.0.0.45 -j DROP

# Verify firewall rules are in place
sudo iptables -L INPUT -n -v | grep 12.0.0.45
sudo iptables -L OUTPUT -n -v | grep 12.0.0.45

# Kill connections to attacker IP
sudo netstat -antp | grep 12.0.0.45 | awk '{print $7}' | cut -d'/' -f1 | xargs -r sudo kill -9

# Verify no connections to attacker IP remain
sudo netstat -antp | grep 12.0.0.45
# Expected: No output (empty)

# Kill connections on port 4444
sudo netstat -antp | grep :4444 | awk '{print $7}' | cut -d'/' -f1 | xargs -r sudo kill -9

# Verify no connections on port 4444
sudo netstat -antp | grep :4444
# Expected: No output (empty)

#check send_db.py running processes
sudo ps aux | grep 'send_db.py'

# Kill send_db.py process
sudo pkill -9 -f send_db.py

# Verify send_db.py is not running
ps aux | grep send_db.py
# Expected: No output (empty)

# Kill nc_upload_share.py process
sudo pkill -9 -f nc_upload_share.py

# Verify nc_upload_share.py is not running
ps aux | grep nc_upload_share.py | grep -v grep
# Expected: No output (empty)

# Kill mail_test.py process
sudo pkill -9 -f mail_test.py

# Verify mail_test.py is not running
ps aux | grep mail_test.py | grep -v grep
# Expected: No output (empty)

# Kill dphelper_v2.4_test_build process
sudo pkill -9 -f dphelper_v2.4_test_build

# Verify dphelper is not running
ps aux | grep dphelper_v2.4_test_build | grep -v grep
# Expected: No output (empty)

# Kill nmap process
sudo pkill -9 -f nmap

# Verify nmap is not running
ps aux | grep nmap | grep -v grep
# Expected: No output (empty)

# Kill any www-data spawned shells
sudo pkill -9 -u www-data -f '/bin/sh'
sudo pkill -9 -u www-data -f '/bin/bash'
sudo pkill -9 -u www-data -f 'nc'

# Verify no shells running as www-data
ps aux | grep www-data | grep -E '/bin/sh|/bin/bash|nc' | grep -v grep
# Expected: No output (empty)
```

### **4. Remove Malicious Files**

```bash
# Remove the reverse shell, attacker tools and data_exfil script
sudo rm -f /var/www/secureskies/secureskies/uploads/reverse6.php
sudo rm -rf /tmp/nmap_transfer/
sudo rm -f /var/www/secureskies/secureskies/send_db.py

# Restart Apache to clear any other remaining processes
sudo systemctl restart apache2

```
