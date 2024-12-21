import os
import logging

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    filename='antivirus.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Örnek tarama kuralları
SUSPICIOUS_EXTENSIONS = [".exe", ".dll"]
VIRUS_SIGNATURES = ["malware", "trojan", "virus"]  # Bu, örnek verilerle simüle edilmiştir.

def scan_file(file_path):
    """
    Dosyayı tarar ve durumuna göre loglama yapar.
    """
    try:
        # Şüpheli dosya kontrolü
        if any(file_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            logging.warning(f"Karantinaya alınacak şüpheli dosya bulundu: {file_path}")
        
        # Virüs tespiti simülasyonu
        with open(file_path, 'r', errors='ignore') as file:
            content = file.read()
            if any(signature in content for signature in VIRUS_SIGNATURES):
                logging.error(f"Virüs tespit edildi: {file_path}")
        
        # Temiz dosyalar için bilgi
        logging.info(f"Temiz dosya tarandı: {file_path}")
    except Exception as e:
        logging.error(f"Dosya taranırken hata oluştu: {file_path} - {e}")

def scan_directory(directory_path):
    """
    Belirtilen dizindeki dosyaları tarar ve loglama yapar.
    """
    logging.info(f"Tarama başlatıldı: {directory_path}")
    try:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path)
        logging.info("Tarama başarıyla tamamlandı.")
    except Exception as e:
        logging.error(f"Tarama sırasında hata oluştu: {e}")

