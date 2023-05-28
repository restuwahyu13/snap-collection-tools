# Snap Collection Tools

Repo ini adalah kumpulan tools yang saya buat, untuk membantu anda semua ketika anda melakukan integrasi dengan [API Services  BI SNAP](https://apidevportal.bi.go.id/snap/api-services).

- **Snap Code** Digunakan untuk mendefinisikan setiap status code, berdasarkan service - service mana saja yang akan digunakan.
- **Snap Credentials** Digunakan untukk memvalidasi privateKey atau publicKey, yang diberikan oleh client saat melakukan generate `signature-auth` / `signature-service` atau ketika melakukan verifikasi signature yang di cocokan dari environment.
- **Snap Response** Digunakan untuk menampilkan success response dan error response berdasarkan service yang akan digunakan.
- **Snap Token** Digunakan untuk melakukan enkripsi data saat melakukan proses `signature-auth` dan `access-token/b2b`, dengan menggunakan metode asymmetric pattern atau symmetric pattern.
- **Snap Validation** Digunakan untuk memvalidasi setiap headers atau request body yang diberikan dan juga bisa untuk membuat custom error message.
- **Snap Verify** Digunakan untuk verifikasi signature yang diberikan oleh client, ketika client mengakses service yang akan digunakan contoh `balance-inquiry`.