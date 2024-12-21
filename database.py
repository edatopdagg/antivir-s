import os
import sqlite3

def initialize_database():
    """
    Virüs hash'lerini içeren SQLite veritabanını oluşturur ve örnek veriler ekler.
    """
    db_file = "./VirusHashDB.db"

    # Eğer veritabanı zaten varsa oluşturma işlemini atla
    if os.path.exists(db_file):
        print("Veritabanı zaten mevcut, oluşturma atlanıyor.")
        return

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS VirusHashDB (
        hash TEXT PRIMARY KEY,
        name TEXT,
        type TEXT,
        threat_level TEXT
    )
    ''')

    sample_data = [
        ("f4c3fa43b5bdfaa0205990d25ce51c5a", "Trojan.Win32.Emotet.471040.A", "Trojan", "High"),
        ("ab56b4d92b40713acc5af89985d9a2d6", "Trojan.Win32.ZLoader.103856.B", "Trojan", "High"),
        ("d41d8cd98f00b204e9800998ecf8427e", "Worm.Win32.MyDoom.A", "Worm", "Medium"),
        ("b2a80d8f91d7bece5ac8baf2e9f1b643", "Trojan.Win32.MalDoc.89301.C", "Trojan", "Medium"),
        ("8f14e45fceea167a5a36dedd4bea2543", "Virus.Win32.Ryuk.431060.D", "Ransomware", "High"),
        ("3c59dc048e885024e7a1a5a60e3b7f41", "Trojan.Win32.Sodinokibi.237208.B", "Ransomware", "High"),
        ("9c56f43bc832cb2d557e75890256b915", "Backdoor.Win32.Gh0st.847292.A", "Backdoor", "High"),
        ("23ab953b1831c7c9b227ea5377174de5", "Trojan.Win32.TrickBot.512323.C", "Trojan", "High"),
        ("c4ca4238a0b923820dcc509a6f75849b", "Ransomware.Win32.Crylock.116047.D", "Ransomware", "High"),
        ("d3d9446802a44259755d38e6d163e820", "Malware.Win32.Adware.234705.A", "Adware", "Low")
    ]

    cursor.executemany('''
    INSERT OR REPLACE INTO VirusHashDB (hash, name, type, threat_level)
    VALUES (?, ?, ?, ?)
    ''', sample_data)

    conn.commit()
    conn.close()
    print("Veritabanı oluşturuldu ve veriler başarıyla eklendi.")
