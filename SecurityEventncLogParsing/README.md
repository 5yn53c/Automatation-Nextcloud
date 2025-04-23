#Untuk menjadwalkan script agar jalan otomatis:
1. Masuk Ke Cron
   crontab -e
2. Tambahkan baris agar di jalankan per-5 menit
   */5 * * * * python3 /usr/local/bin/filter_virus_failedlogin_json.py

Interval bisa diubah dengan mengikuti standar
