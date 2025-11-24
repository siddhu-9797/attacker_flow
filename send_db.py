#!/usr/bin/env python3
import os, time, json, requests

FILE = "/var/www/secureskies/secureskies/db.json"         # webserver db.json 
URL  = "http://12.0.0.45:8001/"        #  VM receive.py 

print("Starting send_db.py...")
while True:
    print("Checking for new records to send...")
    try:
        if os.path.exists(FILE):
            with open(FILE, "r+") as f:
                lines = f.readlines()

            payload = [json.loads(line) for line in lines if line.strip()]
            print(f"Sending {len(payload)} record(s)...")
            r = requests.post(URL, json=payload, timeout=5)

        

        else:
            print(f"File {FILE} does not exist. Retrying in 5 seconds...")
        time.sleep(5)

    except Exception as e:
        print(f"Error: {e}")
        continue

