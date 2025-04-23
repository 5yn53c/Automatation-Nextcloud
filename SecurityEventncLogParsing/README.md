# Untuk menjadwalkan script agar jalan otomatis:
1. Masuk Ke Cron
   crontab -e
2. Tambahkan baris agar di jalankan per-5 menit
   */5 * * * * python3 /usr/local/bin/filter_virus_failedlogin_json.py
   
   Interval bisa diubah dengan mengikuti standar
   ![image](https://github.com/user-attachments/assets/1af20dfc-842a-44ea-9759-d166e5553008)

   A. Minute
   Menit saat command akan dijalankan, antara 0 sampai 59.
   
   B. Hour
   Jam saat command akan dijalankan, dengan rentang 0-23 (format waktu 24 jam).
   
   C. Day of the month
   Hari dalam suatu bulan yang diinginkan user untuk menjalankan command, dengan rentang 1-31.
   
   D. Month
   Bulan yang user inginkan untuk menjalankan command, dengan rentang 1-12 untuk Januari sampai Desember.
   E. Day of the week
   Hari dalam satu minggu saat perintah akan dijalankan, dengan rentang 0-6 yang mewakili Minggu sampai Sabtu.
   Dalam beberapa sistem, value 7 mewakili hari Minggu.
   
   Sebagai contoh, kalau Anda ingin menyiapkan cron job untuk menjalankan root/backup.sh setiap Jumat pukul 17.37, cron command Anda akan       menjadi seperti ini:

   **37 17 * * 5 root/backup.sh**
   Value 37 dan 17 di atas mewakili pukul 17.37. Dua tanda bintang untuk value Day of the month dan Month mewakili value apa pun yang           memungkinkan. Artinya, tugas tersebut akan diulang pada semua tanggal dan semua bulan. Terakhir, value 5 mewakili hari Jumat.
   Deretan   angka tersebut kemudian diikuti oleh lokasi tugas.


