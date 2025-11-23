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

# On the secureskies web server
sudo iptables -I INPUT 1 -s 12.0.0.45 -j DROP
sudo iptables -I OUTPUT 1 -d 12.0.0.45 -j DROP

# Kill active connections and processes
# Kill connections to attacker IP
sudo lsof -ti TCP@12.0.0.45 | xargs -r sudo kill -9

# Kill connections on port 4444
sudo lsof -ti :4444 | xargs -r sudo kill -9

sudo pkill -9 -f send_db.py

sudo pkill -9 -f nc_upload_share.py
sudo pkill -9 -f mail_test.py
sudo pkill -9 -f dphelper_v2.4_test_build
sudo pkill -9 -f nmap

----

# Kill any www-data spawned shells
sudo pkill -9 -u www-data -f '/bin/sh'
sudo pkill -9 -u www-data -f '/bin/bash'
sudo pkill -9 -u www-data -f 'nc'
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
