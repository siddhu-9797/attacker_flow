#!/usr/bin/env python3
import os, time, json, fcntl, requests

FILE = "/var/www/secureskies/secureskies/db.json"         # webserver db.json 
URL  = "http://12.0.0.45:8001/"        #  VM receive.py 

while True:
    try:
        if os.path.exists(FILE) and os.path.getsize(FILE) > 0:
            with open(FILE, "r+") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                lines = f.readlines()
                f.seek(0)
                f.truncate()
                fcntl.flock(f, fcntl.LOCK_UN)

            payload = [json.loads(line) for line in lines if line.strip()]
            print(f"Sending {len(payload)} record(s)...")
            r = requests.post(URL, json=payload, timeout=5)

            if r.status_code >= 300:
                print(f"Send failed ({r.status_code}), restoring file")
                with open(FILE, "a") as f:
                    f.writelines(lines)

        time.sleep(5)

    except Exception as e:
        print("Error:", e)
        time.sleep(5)

