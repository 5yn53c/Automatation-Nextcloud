# Automation Script
This script aims to send nextcloud.log to SIEM, however, not all logs but only information about failed logins and information about which files are infected with malware based on AV detection in Nextcloud.

## Step Implementation
### Create File and add code
   touch example.py
### Add Cron Script
   */5 * * * * python3 /usr/bin/python3 /path/to/file.py
   
   The interval can be changed by following the standards.

### Send Log To SIEM
   Create File On /etc/rsyslog.d/ and add config bellow

   module(load="imfile")

   input(type="imfile"
         File="Path Log File"
         Tag="security_event:"
         Severity="info"
         Facility="local1")

   local1.*                        @@ip-siem:port_siem
