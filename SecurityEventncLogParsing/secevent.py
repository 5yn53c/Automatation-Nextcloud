import json
import os
import re

LOG_INPUT = "/var/www/html/nextcloud/data/nextcloud.log"
LOG_OUTPUT = "/var/log/nextcloud/security_events.log"
LAST_TIME_FILE = "/var/log/nextcloud/.lasttime"  # untuk nyimpen waktu terakhir

# Regex patterns
antivirus_regex = re.compile(r'Virus (?P<virus>[\w\.\-]+) is detected')
failed_login_regex = re.compile(r'Login failed: (?P<user>\w+) \(Remote IP: (?P<ip>[\d\.]+)\)')

# Load last processed time
if os.path.exists(LAST_TIME_FILE):
    with open(LAST_TIME_FILE, "r") as f:
        last_time = f.read().strip()
else:
    last_time = None

new_last_time = last_time  # Default, supaya kalau nggak ada update tetap aman

# Process logs
new_logs = []
with open(LOG_INPUT, "r") as f:
    for line in f:
        try:
            log = json.loads(line)
            log_time = log.get("time")

            if not log_time:
                continue

            # Langsung pakai time tanpa parsing
            formatted_time = log_time

            # Lewatkan log yang sudah diproses
            if last_time and log_time <= last_time:
                continue

            req_id = log.get("reqId")
            message = log.get("message", "")
            base_entry = {
                "reqId": req_id,
                "time": formatted_time,
                "remoteAddr": log.get("remoteAddr"),
                "user": log.get("user"),
                "method": log.get("method"),
                "url": log.get("url"),
                "userAgent": log.get("userAgent"),
                "version": log.get("version"),
                "originalMessage": message
            }

            # Deteksi virus
            match_virus = antivirus_regex.search(message)
            if match_virus:
                base_entry.update({
                    "type": "virus_detected",
                    "app": "files_antivirus",
                    "virus": match_virus.group("virus"),
                    "message": message
                })
                new_logs.append(base_entry)
                new_last_time = log_time
                continue

            # Deteksi failed login
            match_login = failed_login_regex.search(message)
            if match_login:
                base_entry.update({
                    "type": "failed_login",
                    "app": "authentication",
                    "username": match_login.group("user"),
                    "message": message
                })
                new_logs.append(base_entry)
                new_last_time = log_time

        except json.JSONDecodeError:
            continue

# Write new logs
if new_logs:
    os.makedirs(os.path.dirname(LOG_OUTPUT), exist_ok=True)
    with open(LOG_OUTPUT, "a") as f:
        for entry in new_logs:
            f.write(json.dumps(entry) + "\n")

    # Update last time
    with open(LAST_TIME_FILE, "w") as f:
        f.write(new_last_time)