import json
import logging
import os
import threading
import time
from tkinter import filedialog

from database import initialize_database
from scanner import scan_directory, load_virus_database, restore_clean_file, check_virus, get_all_files, calculate_hash

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    filename='antivirus.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Modern tasarım için CustomTkinter kullanımı
try:
    import customtkinter as ctk
    ctk.set_appearance_mode("dark")  # Temayı karanlık moda ayarla
    ctk.set_default_color_theme("blue")  # Varsayılan renk temasını ayarla
except ImportError:
    raise ImportError("CustomTkinter kütüphanesini yüklemek için 'pip install customtkinter' komutunu kullanın.")

# Bilgisayar adı
computer_name = os.getenv("COMPUTERNAME", "Bilinmeyen Bilgisayar")

# Uygulama ana penceresi
root = ctk.CTk()
root.title("Shield Pro Antivirus")
root.geometry("800x600")  # Bu satır isterseniz kalabilir; tam ekran için etkisiz olacak.
root.resizable(True, True)
root.attributes('-fullscreen', True)  # Tam ekran modu etkinleştirildi

# Tam ekran modundan çıkış için Esc tuşu
def exit_fullscreen(event=None):
    root.attributes('-fullscreen', False)

# Esc tuşuna basıldığında tam ekran modundan çıkışı bağla
root.bind("<Escape>", exit_fullscreen)

# Renk paleti ve stil ayarları
background_color = "#2b2f3a"
highlight_color = "#3c4150"
text_color = "#ffffff"

root.configure(bg=background_color)

# Başlık kısmı
title_label = ctk.CTkLabel(root, text="Shield Pro Antivirus", font=("Poppins", 26, "bold"))
title_label.pack(pady=20)

# Hoş geldiniz mesajı
welcome_msg = ctk.CTkLabel(root, text=f"Merhaba {computer_name}!", font=("Poppins", 16))
welcome_msg.pack(pady=10)

# Saat ve tarih göstergesi
time_label = ctk.CTkLabel(root, text="", font=("Poppins", 12))
time_label.pack(pady=10)

def update_time():
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    time_label.configure(text=current_time)
    root.after(1000, update_time)

update_time()

# İlerleme çubuğu
progress_color = "#008000"
progress = ctk.CTkProgressBar(root, width=500,progress_color=progress_color, fg_color=highlight_color)
progress.pack(pady=20)

#yeni buton rengi
button_color = "#008000"

#diğer buton
button_color2 = "#357EC7"

# Tarama işlemleri için butonlar
button_frame = ctk.CTkFrame(root, fg_color=highlight_color, corner_radius=15)
button_frame.pack(pady=20, padx=20, fill="x")

btn_select_directory = ctk.CTkButton(button_frame, text="Klasör Tarama", command=lambda: threading.Thread(target=select_directory).start(),fg_color=button_color, hover_color=button_color)
btn_select_directory.pack(pady=10, padx=20)

btn_full_scan = ctk.CTkButton(button_frame, text="Tüm Bilgisayarı Tara", command=lambda: threading.Thread(target=scan_entire_computer).start(),fg_color=button_color, hover_color=button_color)
btn_full_scan.pack(pady=10, padx=20)

btn_scan_quarantine = ctk.CTkButton(button_frame, text="Karantinayı Tara", command=lambda: threading.Thread(target=scan_quarantine).start(),fg_color=button_color, hover_color=button_color)
btn_scan_quarantine.pack(pady=10, padx=20)

# Raporları görüntüleme butonu
btn_view_reports = ctk.CTkButton(root, text="Raporları Görüntüle", command=lambda: threading.Thread(target=view_reports).start(),fg_color=button_color2, 
                                  hover_color=button_color2)
btn_view_reports.pack(pady=10, ipadx=10)

# Logları görüntüleme butonu
btn_view_logs = ctk.CTkButton(root, text="Logları Göster", command=lambda: threading.Thread(target=view_logs).start(),fg_color=button_color2, 
                                  hover_color=button_color2)
btn_view_logs.pack(pady=10, ipadx=10)

# Çıkış butonu
btn_exit = ctk.CTkButton(root, text="Çıkış", command=root.quit, fg_color="red", hover_color="#E50914")
btn_exit.pack(pady=20)

# Tarama fonksiyonları
def select_directory():
    directory = filedialog.askdirectory()
    if directory:
        progress.start()
        logging.info(f"Klasör seçildi: {directory}")
        threading.Thread(target=scan_directory_and_show_results, args=(directory,)).start()

def scan_directory_and_show_results(directory):
    results = scan_directory(directory, virus_database, quarantine_directory, output_file="scan_results.json")
    root.after(0, lambda: show_scan_results(results))

def scan_entire_computer():
    progress.start()
    logging.info("Tüm bilgisayar taranıyor...")
    threading.Thread(target=scan_entire_computer_and_show_results).start()

def scan_entire_computer_and_show_results():
    results = scan_directory("C:/", virus_database, quarantine_directory, output_file="scan_results.json")
    root.after(0, lambda: show_scan_results(results))

def scan_quarantine():
    progress.start()
    logging.info("Karantina taranıyor...")
    threading.Thread(target=scan_quarantine_and_show_results).start()

def scan_quarantine_and_show_results():
    results = []
    for file_path in get_all_files(quarantine_directory):
        file_hash = calculate_hash(file_path, 'md5')
        if file_hash:
            is_infected = check_virus(file_hash, virus_database)
            if is_infected:
                os.remove(file_path)
                results.append({"file_path": file_path, "hash": file_hash, "status": "Infected and Deleted"})
                logging.error(f"Virüs tespit edildi ve silindi: {file_path}")
            else:
                restore_clean_file(file_path, "./restored_files")
                results.append({"file_path": file_path, "hash": file_hash, "status": "Clean and Restored"})
                logging.info(f"Temiz dosya geri yüklendi: {file_path}")
        else:
            results.append({"file_path": file_path, "hash": None, "status": "Error"})
            logging.warning(f"Dosya taranırken hata oluştu: {file_path}")

    # Tarama sonuçlarını JSON dosyasına yazdır
    try:
        with open("scan_results.json", "w") as json_file:
            json.dump(results, json_file, indent=4)
        logging.info("Tarama sonuçları 'results.json' dosyasına kaydedildi.")
    except Exception as e:
        logging.error(f"Sonuçlar kaydedilirken bir hata oluştu: {e}")

    root.after(0, lambda: show_scan_results(results))

def show_scan_results(results):
    progress.stop()
    results_window = ctk.CTkToplevel(root)
    results_window.title("Tarama Sonuçları")
    results_window.geometry("500x400")

    label = ctk.CTkLabel(results_window, text=f"{len(results)} dosya tarandı. Sonuçlar 'scan_results.json' dosyasına kaydedildi.")
    label.pack(pady=20)

    close_button = ctk.CTkButton(results_window, text="Kapat", command=results_window.destroy)
    close_button.pack(pady=10)

# Logları görüntüleme fonksiyonu
def view_logs():
    try:
        log_window = ctk.CTkToplevel(root)
        log_window.title("Log Kayıtları")
        log_window.geometry("600x400")

        log_frame = ctk.CTkScrollableFrame(log_window, width=580, height=350)
        log_frame.pack(pady=10, padx=10)

        if os.path.exists('antivirus.log'):
            with open('antivirus.log', 'r') as log_file:
                for line in log_file:
                    label = ctk.CTkLabel(log_frame, text=line.strip(), font=("Poppins", 12), anchor="w")
                    label.pack(fill="x", pady=2)
        else:
            label = ctk.CTkLabel(log_frame, text="Log dosyası bulunamadı.", font=("Poppins", 12))
            label.pack(pady=10)

        close_button = ctk.CTkButton(log_window, text="Kapat", command=log_window.destroy)
        close_button.pack(pady=10)

    except Exception as e:
        logging.error(f"Logları görüntülerken hata oluştu: {e}")

# Raporları görüntüleme fonksiyonu
def view_reports():
    try:
        # scan_results.json dosyasını oku
        if os.path.exists("scan_results.json"):
            with open("scan_results.json", "r") as file:
                scan_results = json.load(file)
        else:
            scan_results = []

        # Yeni bir pencere oluştur
        report_window = ctk.CTkToplevel(root)
        report_window.title("Raporlar")
        report_window.geometry("600x400")

        # Sonuçları kaydırılabilir bir alanda göster
        report_frame = ctk.CTkScrollableFrame(report_window, width=580, height=350)
        report_frame.pack(pady=10, padx=10)

        if scan_results:
            for result in scan_results:
                status = result.get("status", "Unknown")
                file_path = result.get("file_path", "Bilinmeyen Dosya")

                # Duruma göre renk belirle
                if status.lower() == "clean":
                    text_color = "#00FF00"  # Yeşil
                elif status.lower() == "infected and quarantined":
                    text_color = "#FF0000"  # Kırmızı
                elif status.lower()=="clean and restored":
                    text_color = "#00FF00"
                elif status.lower()=="infected and deleted":
                    text_color = "#FF0000"
                else:
                    text_color = "#FFFFFF"  # Beyaz

                # Sonuçları etikette göster
                label = ctk.CTkLabel(report_frame, text=f"{file_path}: {status}", font=("Poppins", 12), anchor="w",
                                     text_color=text_color)
                label.pack(fill="x", pady=2)
        else:
            label = ctk.CTkLabel(report_frame, text="Herhangi bir tarama sonucu bulunamadı.", font=("Poppins", 12))
            label.pack(pady=10)

        close_button = ctk.CTkButton(report_window, text="Kapat", command=report_window.destroy)
        close_button.pack(pady=10)

    except Exception as e:
        logging.error(f"Raporları görüntülerken hata oluştu: {e}")


# Veritabanı ve dizinleri başlatma
initialize_database()
virus_database = load_virus_database("./VirusHashDB.db")
quarantine_directory = "./quarantine"

# Ana döngü
root.mainloop()