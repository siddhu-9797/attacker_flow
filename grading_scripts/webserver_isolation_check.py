#!/usr/bin/env python3
"""
Grading Script: Web Server Isolation Check
Verifies that the web server has been properly isolated from the attacker IP.

Checks:
1. Attacker IP is blocked in iptables firewall
2. No active connections to attacker IP exist
3. Attacker IP is not reachable from web server
"""

import subprocess
import sys
import re

ATTACKER_IP = "12.0.0.45"
TOTAL_POINTS = 100
score = 0

def run_command(cmd, shell=False):
    """Run a command and return output, return code, and stderr"""
    try:
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except Exception as e:
        return "", str(e), -1

def check_firewall_rules():
    """Check if attacker IP is blocked in iptables"""
    print("\n" + "="*70)
    print("CHECK 1: Firewall Rules (40 points)")
    print("="*70)
    
    points = 0
    max_points = 40
    
    # Check INPUT chain
    stdout, stderr, rc = run_command(f"sudo iptables -L INPUT -n -v", shell=True)
    if ATTACKER_IP in stdout and "DROP" in stdout:
        print(f"✓ INPUT chain blocks {ATTACKER_IP} (+20 points)")
        points += 20
    else:
        print(f"✗ INPUT chain does not block {ATTACKER_IP} (0 points)")
        print(f"  Hint: sudo iptables -I INPUT 1 -s {ATTACKER_IP} -j DROP")
    
    # Check OUTPUT chain
    stdout, stderr, rc = run_command(f"sudo iptables -L OUTPUT -n -v", shell=True)
    if ATTACKER_IP in stdout and "DROP" in stdout:
        print(f"✓ OUTPUT chain blocks {ATTACKER_IP} (+20 points)")
        points += 20
    else:
        print(f"✗ OUTPUT chain does not block {ATTACKER_IP} (0 points)")
        print(f"  Hint: sudo iptables -I OUTPUT 1 -d {ATTACKER_IP} -j DROP")
    
    print(f"\nFirewall Rules Score: {points}/{max_points}")
    return points

def check_active_connections():
    """Check if there are any active connections to attacker IP"""
    print("\n" + "="*70)
    print("CHECK 2: No Active Connections (30 points)")
    print("="*70)
    
    points = 0
    max_points = 30
    
    # Check using netstat
    stdout, stderr, rc = run_command(f"sudo netstat -antp 2>/dev/null | grep {ATTACKER_IP}", shell=True)
    
    if stdout.strip() == "":
        print(f"✓ No active connections to {ATTACKER_IP} (+30 points)")
        points += 30
    else:
        print(f"✗ Active connections to {ATTACKER_IP} found (0 points)")
        print(f"  Active connections:\n{stdout}")
        print(f"  Hint: Kill these connections using:")
        print(f"  sudo netstat -antp | grep {ATTACKER_IP} | awk '{{print $7}}' | cut -d'/' -f1 | xargs -r sudo kill -9")
    
    print(f"\nActive Connections Score: {points}/{max_points}")
    return points

def check_network_reachability():
    """Check if attacker IP is reachable from web server"""
    print("\n" + "="*70)
    print("CHECK 3: Network Reachability (30 points)")
    print("="*70)
    
    points = 0
    max_points = 30
    
    # Use ping to check reachability (send 3 packets, timeout 3 seconds)
    stdout, stderr, rc = run_command(f"ping -c 3 -W 3 {ATTACKER_IP}", shell=True)
    
    if rc != 0:
        print(f"✓ {ATTACKER_IP} is NOT reachable (blocked/unreachable) (+30 points)")
        points += 30
    else:
        print(f"✗ {ATTACKER_IP} is still reachable (0 points)")
        print(f"  Ping output:\n{stdout}")
        print(f"  Hint: Ensure firewall rules are properly configured")
    
    print(f"\nNetwork Reachability Score: {points}/{max_points}")
    return points

def main():
    print("="*70)
    print("WEB SERVER ISOLATION GRADING SCRIPT")
    print("="*70)
    print(f"Target: Verify isolation from attacker IP {ATTACKER_IP}")
    print(f"Total Points: {TOTAL_POINTS}")
    
    global score
    
    # Run all checks
    score += check_firewall_rules()
    score += check_active_connections()
    score += check_network_reachability()
    
    # Final score
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    print(f"Total Score: {score}/{TOTAL_POINTS}")
    percentage = (score / TOTAL_POINTS) * 100
    print(f"Percentage: {percentage:.1f}%")
    
    print("="*70)
    
    # Exit with appropriate code
    sys.exit(0 if score == TOTAL_POINTS else 1)

if __name__ == "__main__":
    main()
