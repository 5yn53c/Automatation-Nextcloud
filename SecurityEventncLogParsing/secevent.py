import json
import os
import re
from datetime import datetime

LOG_INPUT = "/var/www/html/nextcloud/data/nextcloud.log"
LOG_OUTPUT = "/var/log/nextcloud/security_events.log"
LAST_TIME_FILE = "/var/log/nextcloud/last_time.txt"

# Regex patterns
antivirus_regex = re.compile(r'Virus (?P<virus>[\w\.\-]+) is detected')
infected_deleted_regex = re.compile(r'Infected file deleted\.')
failed_login_regex = re.compile(r'Login failed: (?P<user>[\w\-]+) \(Remote IP: (?P<ip>[\d\.]+)\)')

# Load last processed time
last_time = None
if os.path.exists(LAST_TIME_FILE):
    with open(LAST_TIME_FILE, "r") as f:
        last_time_text = f.read().strip()
        if last_time_text:
            last_time = datetime.strptime(last_time_text, "%Y-%m-%dT%H:%M:%S+00:00")

# Load existing reqIds to prevent duplicate processing
existing_ids = set()
if os.path.exists(LOG_OUTPUT):
    with open(LOG_OUTPUT, "r") as f:
        for line in f:
            try:
                log_entry = json.loads(line.strip())
                if "reqId" in log_entry:
                    existing_ids.add(log_entry["reqId"])
            except json.JSONDecodeError:
                continue

# Process logs
new_logs = []
with open(LOG_INPUT, "r") as f:
    for line in f:
        try:
            log = json.loads(line)
            req_id = log.get("reqId")
            if not req_id or req_id in existing_ids:
                continue

            log_time = log["time"]
            if last_time:
                pass  # Time filtering skipped

            message = log.get("message", "")
            base_entry = {
                "reqId": req_id,
                "time": log_time,
                "remoteAddr": log.get("remoteAddr"),
                "user": log.get("user"),
                "method": log.get("method"),
                "url": log.get("url"),
                "userAgent": log.get("userAgent"),
                "version": log.get("version"),
                "originalMessage": message
            }

            # Cek virus detected
            match_virus = antivirus_regex.search(message)
            if match_virus:
                base_entry.update({
                    "type": "virus_detected",
                    "app": "files_antivirus",
                    "virus": match_virus.group("virus"),
                    "message": message
                })
                new_logs.append(base_entry)
                existing_ids.add(req_id)
                continue

            # Cek infected file deleted
            match_infected_deleted = infected_deleted_regex.search(message)
            if match_infected_deleted:
                base_entry.update({
                    "type": "infected_file_deleted",
                    "app": "files_antivirus",
                    "message": message
                })
                new_logs.append(base_entry)
                existing_ids.add(req_id)
                continue

            # Cek gagal login
            match_login = failed_login_regex.search(message)
            if match_login:
                base_entry.update({
                    "type": "failed_login",
                    "app": "authentication",
                    "username": match_login.group("user"),
                    "remoteIp": match_login.group("ip"),
                    "message": message
                })
                new_logs.append(base_entry)
                existing_ids.add(req_id)

        except json.JSONDecodeError:
            continue

# Write new logs
if new_logs:
    with open(LOG_OUTPUT, "a") as f:
        for entry in new_logs:
            f.write(json.dumps(entry) + "\n")

# Update LAST_TIME_FILE dengan waktu sekarang
with open(LAST_TIME_FILE, "w") as f:
    f.write(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00"))
