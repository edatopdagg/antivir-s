import os
import hashlib
import shutil
import sqlite3
import json

def get_all_files(directory):
    """
    Belirtilen klasördeki tüm dosyaları ve alt klasörlerdeki dosyaları bulur.
    """
    for root, _, files in os.walk(directory):
        for file in files:
            yield os.path.join(root, file)

def calculate_hash(file_path, algorithm='md5'):
    """
    Bir dosyanın hash değerini hesaplar.
    :param file_path: Dosyanın yolu
    :param algorithm: Kullanılacak hash algoritması ('md5', 'sha1', 'sha256' gibi)
    :return: Hash değeri veya hata durumunda None
    """
    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):  # 4KB parça parça oku
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def load_virus_database(db_file):
    """
    SQLite veritabanından virüs hash'lerini yükler.
    :param db_file: Veritabanı dosya yolu
    :return: Virüs hash'lerinin listesi
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM VirusHashDB")
        virus_hashes = [row[0] for row in cursor.fetchall()]
        conn.close()
        return virus_hashes
    except Exception as e:
        print(f"Error loading virus database: {e}")
        return []

def check_virus(hash_value, virus_database):
    """
    Hash'in virüs veritabanında olup olmadığını kontrol eder.
    :param hash_value: Kontrol edilecek hash
    :param virus_database: Virüs hash'lerinin listesi
    :return: True (virüs bulundu), False (temiz)
    """
    return hash_value in virus_database

def quarantine_infected_file(file_path, quarantine_directory):
    """
    Enfekte dosyayı karantina klasörüne taşır.
    :param file_path: Taşınacak dosyanın yolu
    :param quarantine_directory: Karantina klasörünün yolu
    """
    try:
        os.makedirs(quarantine_directory, exist_ok=True)
        shutil.move(file_path, quarantine_directory)
        print(f"Infected file moved to quarantine: {file_path}")
    except Exception as e:
        print(f"Error quarantining file {file_path}: {e}")

import json

def scan_directory(directory, virus_database, quarantine_directory, output_file="scan_results.json"):
    """
    Bir dizini tarar, dosyaların hash'lerini çıkarır ve virüs kontrolü yapar.
    :param directory: Taranacak dizin
    :param virus_database: Virüs hash veritabanı
    :param quarantine_directory: Karantina klasörünün yolu
    :param output_file: Tarama sonuçlarının kaydedileceği JSON dosyası
    :return: Tarama sonuçlarının listesi
    """
    results = []
    for file_path in get_all_files(directory):
        print(f"Scanning: {file_path}")
        file_hash = calculate_hash(file_path, 'md5')

        if file_hash:
            is_infected = check_virus(file_hash, virus_database)
            if is_infected:
                quarantine_infected_file(file_path, quarantine_directory)
                results.append({
                    "file_path": file_path,
                    "hash": file_hash,
                    "status": "infected and quarantined"
                })
            else:
                results.append({
                    "file_path": file_path,
                    "hash": file_hash,
                    "status": "clean"
                })
        else:
            results.append({
                "file_path": file_path,
                "hash": None,
                "status": "error"
            })

    # Sonuçları JSON dosyasına yaz
    try:
        with open(output_file, "w", encoding="utf-8") as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Scan results saved to {output_file}")
    except Exception as e:
        print(f"Error writing scan results to JSON: {e}")

    return results


def restore_clean_file(file_path, original_directory):
    """
    Temiz dosyayı karantinadan eski konumuna geri taşır.
    :param file_path: Taşınacak dosyanın yolu
    :param original_directory: Eski konumun yolu
    """
    try:
        os.makedirs(original_directory, exist_ok=True)
        shutil.move(file_path, original_directory)
        print(f"Clean file restored to original location: {file_path}")
    except Exception as e:
        print(f"Error restoring file {file_path}: {e}")
