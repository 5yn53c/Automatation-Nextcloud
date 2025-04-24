import json
import os
import re
from datetime import datetime

LOG_INPUT = "/var/www/html/nextcloud/data/nextcloud.log"
LOG_OUTPUT = "/var/log/nextcloud/security_events.log"

# Regex patterns
antivirus_regex = re.compile(r'Virus (?P<virus>[\w\.\-]+) is detected')
failed_login_regex = re.compile(r'Login failed: (?P<user>\w+) \(Remote IP: (?P<ip>[\d\.]+)\)')

# Load reqIds from output log
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

# Process input log
new_logs = []
with open(LOG_INPUT, "r") as f:
    for line in f:
        try:
            log = json.loads(line)
            req_id = log.get("reqId")
            if not req_id or req_id in existing_ids:
                continue  # Skip logs with existing reqId

            time_obj = datetime.strptime(log["time"], "%Y-%m-%dT%H:%M:%S+00:00")
            formatted_time = time_obj.strftime("%B %d, %Y %H:%M:%S")

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

            # Cek malware
            match_virus = antivirus_regex.search(message)
            if match_virus:
                base_entry.update({
                    "type": "virus_detected",
                    "app": "files_antivirus",
                    "virus": match_virus.group("virus"),
                    "message": message
                })
                new_logs.append(base_entry)
                existing_ids.add(req_id)  # Tambahkan reqId ke existing_ids
                continue

            # Cek gagal login
            match_login = failed_login_regex.search(message)
            if match_login:
                base_entry.update({
                    "type": "failed_login",
                    "app": "authentication",
                    "username": match_login.group("user"),
                    "message": message
                })
                new_logs.append(base_entry)
                existing_ids.add(req_id)  # Tambahkan reqId ke existing_ids

        except json.JSONDecodeError:
            continue

# Append hanya yang unik
if new_logs:
    with open(LOG_OUTPUT, "a") as f:
        for entry in new_logs:
            f.write(json.dumps(entry) + "\n")