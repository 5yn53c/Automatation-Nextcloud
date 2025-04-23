import json
import re
from datetime import datetime

LOG_INPUT = "/var/log/nextcloud/nextcloud.log"
LOG_OUTPUT = "/var/log/nextcloud/security_events.json"

# Regex untuk deteksi virus
virus_pattern = re.compile(
    r'"remoteAddr":"(?P<ip>[^"]+)".*?"user":"(?P<user>[^"]+)".*?"app":"(?P<app>[^"]+)".*?"method":"(?P<method>[^"]+)".*?"url":"(?P<url>[^"]+)".*?"message":"(?P<message>Virus [^"]+?)".*?"exception":.*?"Message":"(?P<virus>Virus [^"]+?)".*?"class":"(?P<modul>OCA\\\\Files_Antivirus.*?)"',
    re.DOTALL
)

# Regex untuk login gagal
login_fail_pattern = re.compile(
    r'"remoteAddr":"(?P<ip>[^"]+)".*?"user":false.*?"message":"Login failed: (?P<user>[^ ]+) \(Remote IP: (?P=ip)\)"',
    re.DOTALL
)

def parse_log_entry(line):
    # Coba parse line ke dict JSON
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

def extract_security_events():
    events = []
    with open(LOG_INPUT, "r") as infile:
        for line in infile:
            log_entry = parse_log_entry(line)
            if not log_entry:
                continue
            log_str = json.dumps(log_entry)

            # Match virus detection
            virus_match = virus_pattern.search(log_str)
            if virus_match:
                events.append({
                    "event": "virus_detected",
                    "ip": virus_match.group("ip"),
                    "user": virus_match.group("user"),
                    "app": virus_match.group("app"),
                    "method": virus_match.group("method"),
                    "file": virus_match.group("url"),
                    "virus": virus_match.group("virus"),
                    "message": virus_match.group("message"),
                    "module": virus_match.group("modul"),
                    "timestamp": log_entry.get("time", datetime.utcnow().isoformat())
                })

            # Match login failure
            login_match = login_fail_pattern.search(log_str)
            if login_match:
                events.append({
                    "event": "login_failed",
                    "ip": login_match.group("ip"),
                    "user": login_match.group("user"),
                    "message": log_entry.get("message", ""),
                    "timestamp": log_entry.get("time", datetime.utcnow().isoformat())
                })

    return events

if __name__ == "__main__":
    found_events = extract_security_events()

    # Simpan dalam format JSON Lines (append mode)
    with open(LOG_OUTPUT, "a") as outfile:
        for event in found_events:
            outfile.write(json.dumps(event) + "\n")