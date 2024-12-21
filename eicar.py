import sqlite3

# Veritabanı bağlantısı
db_file = "./VirusHashDB.db"
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Eicar Test Dosyasını veritabanına ekleme (Doğru hash ile)
eicar_hash = "44d88612fea8a8f36de82e1278abb02f"  # Eicar test dosyasının doğru hash'i
cursor.execute('''
INSERT OR REPLACE INTO VirusHashDB (hash, name, type, threat_level)
VALUES (?, ?, ?, ?)
''', (eicar_hash, "Eicar.TestFile", "Test Virus", "High"))

conn.commit()
conn.close()
