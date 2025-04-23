import json
import re
from datetime import datetime

# Lokasi file log input dan output
LOG_INPUT = "/var/www/html/nextcloud/data/nextcloud.log"
LOG_OUTPUT = "/var/log/nextcloud/security_events.json"

# List untuk menyimpan entri hasil parsing
log_entries = []

# Regex untuk menangkap dua jenis event
antivirus_regex = re.compile(r'Virus (?P<virus>[\w\.\-]+) is detected')
failed_login_regex = re.compile(r'Login failed: (?P<user>\w+) \(Remote IP: (?P<ip>[\d\.]+)\)')

# Membaca dan parsing log
with open(LOG_INPUT, "r") as log_file:
    for line in log_file:
        try:
            log = json.loads(line)
            entry = {
                "time": datetime.strptime(log["time"], "%Y-%m-%dT%H:%M:%S+00:00").strftime("%B %d, %Y %H:%M:%S"),
                "reqId": log.get("reqId"),
                "remoteAddr": log.get("remoteAddr"),
                "userAgent": log.get("userAgent"),
                "version": log.get("version"),
                "method": log.get("method"),
                "url": log.get("url"),
            }

            # Deteksi virus
            if "Virus" in log.get("message", ""):
                match = antivirus_regex.search(log["message"])
                if match:
                    entry.update({
                        "event": "virus_detected",
                        "virus": match.group("virus"),
                        "user": log.get("user"),
                        "message": log["message"],
                        "app": "files_antivirus"
                    })
                    log_entries.append(entry)

            # Gagal login
            elif "Login failed:" in log.get("message", ""):
                match = failed_login_regex.search(log["message"])
                if match:
                    entry.update({
                        "event": "login_failed",
                        "user": match.group("user"),
                        "app": "authentication",
                        "message": log["message"]
                    })
                    log_entries.append(entry)
        except json.JSONDecodeError:
            continue  # Lewati baris yang tidak valid JSON

# Simpan ke file JSON
with open(LOG_OUTPUT, "w") as out:
    json.dump(log_entries, out, indent=2)

print(f"[+] Security events berhasil disimpan di {LOG_OUTPUT}")
