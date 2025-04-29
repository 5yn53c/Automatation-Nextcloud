# Automation Script
## Change to Cron Mode
   crontab -e
## Add Cron Script
   */5 * * * * python3 /usr/bin/python3 /path/to/file.py
   
   Interval bisa diubah dengan mengikuti standar

## Send Log To SIEM
   Create File On /etc/rsyslog.d/ and add config bellow

   module(load="imfile")

   input(type="imfile"
         File="Path Log File"
         Tag="security_event:"
         Severity="info"
         Facility="local1")

   local1.*                        @@ip-siem:port_siem
