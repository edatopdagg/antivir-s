import os
import logging
import uuid
import time

# Loglama ayarları
log_format = "%(asctime)s - %(name)s - %(levelname)s - [%(module)s.%(funcName)s] - [Transaction ID: %(transaction_id)s] - [User: %(user)s] - %(message)s"

class CustomLogAdapter(logging.LoggerAdapter):
    """
    Loglara ek bağlam bilgisi (transaction_id ve user) eklemek için adapte edilmiş bir logger.
    """
    def process(self, msg, kwargs):
        return f"{msg}", {**kwargs, 'extra': {**self.extra, **kwargs.get('extra', {})}}

# Root logger'ı yapılandır
logging.basicConfig(level=logging.INFO, filename='antivirus.log', filemode='a', format=log_format)
logger = CustomLogAdapter(logging.getLogger("AntivirusLogger"), {"transaction_id": "-", "user": "system"})

# Transaction ID oluşturucu
def generate_transaction_id():
    return str(uuid.uuid4())

# Örnek tarama kuralları
SUSPICIOUS_EXTENSIONS = [".exe", ".dll"]
VIRUS_SIGNATURES = ["malware", "trojan", "virus"]  # Bu, örnek verilerle simüle edilmiştir.

def scan_file(file_path, user):
    """
    Dosyayı tarar ve durumuna göre loglama yapar.
    """
    transaction_id = generate_transaction_id()  # Her işlem için benzersiz ID oluştur
    start_time = time.time()  # İşlem başlangıç zamanı

    try:
        logger.info(f"Dosya taranıyor: {file_path}", extra={"transaction_id": transaction_id, "user": user})
        
        # Şüpheli dosya kontrolü
        if any(file_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            logger.warning(f"Karantinaya alınacak şüpheli dosya bulundu: {file_path}",
                           extra={"transaction_id": transaction_id, "user": user})
        
        # Virüs tespiti simülasyonu
        with open(file_path, 'r', errors='ignore') as file:
            content = file.read()
            if any(signature in content for signature in VIRUS_SIGNATURES):
                logger.error(f"Virüs tespit edildi: {file_path}",
                             extra={"transaction_id": transaction_id, "user": user})
        
        # Temiz dosyalar için bilgi
        logger.info(f"Temiz dosya tarandı: {file_path}", extra={"transaction_id": transaction_id, "user": user})
    except Exception as e:
        logger.error(f"Dosya taranırken hata oluştu: {file_path} - {e}",
                     extra={"transaction_id": transaction_id, "user": user})
    finally:
        # İşlem süresi
        end_time = time.time()
        logger.info(f"İşlem tamamlandı. Süre: {end_time - start_time:.2f} saniye",
                    extra={"transaction_id": transaction_id, "user": user})

def scan_directory(directory_path, user="system"):
    """
    Belirtilen dizindeki dosyaları tarar ve loglama yapar.
    """
    transaction_id = generate_transaction_id()
    logger.info(f"Tarama başlatıldı: {directory_path}", extra={"transaction_id": transaction_id, "user": user})
    
    try:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path, user)
        logger.info("Tarama başarıyla tamamlandı.", extra={"transaction_id": transaction_id, "user": user})
    except Exception as e:
        logger.error(f"Tarama sırasında hata oluştu: {e}", extra={"transaction_id": transaction_id, "user": user})

# Örnek kullanım
scan_directory("C:/Users/Kullanıcı/Desktop", user="test_user")
