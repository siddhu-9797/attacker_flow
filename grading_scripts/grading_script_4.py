#!/usr/bin/env python3
"""
Grading Script: send_db.py Cleanup Check
Verifies that the malicious send_db.py script has been properly removed.

Checks:
1. No send_db.py process is running (15 points)
2. send_db.py file is removed from disk (15 points)
"""

import subprocess
import sys
import os

SEND_DB_PATH = "/var/www/secureskies/secureskies/send_db.py"
TOTAL_POINTS = 30
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

def check_process_stopped():
    """Check if send_db.py process is still running"""
    print("\n" + "="*70)
    print("CHECK 1: send_db.py Process Status (15 points)")
    print("="*70)

    points = 0
    max_points = 15

    # Check using ps command
    stdout, stderr, rc = run_command("ps aux | grep 'send_db.py' | grep -v grep", shell=True)

    if stdout.strip() == "":
        print(f"✓ No send_db.py process is running (+15 points)")
        points += 15
    else:
        print(f"✗ send_db.py process is still running (0 points)")
        print(f"  Running process:\n{stdout}")
        print(f"  Hint: Kill the process using:")
        print(f"   sudo pkill -9 -f send_db.py")

    print(f"\nProcess Status Score: {points}/{max_points}")
    return points

def check_file_removed():
    """Check if send_db.py file is removed from disk"""
    print("\n" + "="*70)
    print("CHECK 2: send_db.py File Removal (15 points)")
    print("="*70)

    points = 0
    max_points = 15

    # Check if file exists
    if not os.path.exists(SEND_DB_PATH):
        print(f"✓ {SEND_DB_PATH} has been removed (+15 points)")
        points += 15
    else:
        print(f"✗ {SEND_DB_PATH} still exists on disk (0 points)")
        print(f"  File details:")
        stdout, stderr, rc = run_command(f"ls -lh {SEND_DB_PATH}", shell=True)
        if stdout.strip():
            print(f"   File details:\n{stdout}")
        print(f"  Hint: Remove the file using:")
        print(f"   sudo rm -f {SEND_DB_PATH}")

    print(f"\nFile Removal Score: {points}/{max_points}")
    return points

def main():
    print("="*70)
    print("SEND_DB.PY CLEANUP GRADING SCRIPT")
    print("="*70)
    print("Target: Verify send_db.py process is stopped and file is removed")
    print(f"Total Points: {TOTAL_POINTS}")

    global score

    # Run all checks
    score += check_process_stopped()
    score += check_file_removed()

    # Final score
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    print(f"Total Score: {score}/{TOTAL_POINTS}")
    percentage = (score / TOTAL_POINTS) * 100
    print(f"Percentage: {percentage:.1f}%")

    if score == TOTAL_POINTS:
        print("\n✓ ALL CHECKS PASSED - send_db.py has been properly cleaned up!")
    else:
        print("\n✗ SOME CHECKS FAILED - send_db.py cleanup incomplete")

    print("="*70)

    # Exit with appropriate code
    sys.exit(0 if score == TOTAL_POINTS else 1)

if __name__ == "__main__":
    main()
