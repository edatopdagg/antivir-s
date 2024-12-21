import json
import os
import tkinter as tk
from tkinter import ttk, filedialog
from PIL import Image, ImageTk
import threading
from scanner import scan_directory, load_virus_database, restore_clean_file, check_virus, get_all_files, calculate_hash
from database import initialize_database
import time

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

# Çıkış butonu
btn_exit = ctk.CTkButton(root, text="Çıkış", command=root.quit, fg_color="red", hover_color="#E50914")
btn_exit.pack(pady=20)

# Tarama fonksiyonları
def select_directory():
    directory = filedialog.askdirectory()
    if directory:
        progress.start()
        threading.Thread(target=scan_directory_and_show_results, args=(directory,)).start()


def scan_directory_and_show_results(directory):
    results = scan_directory(directory, virus_database, quarantine_directory, output_file="scan_results.json")
    root.after(0, lambda: show_scan_results(results))


def scan_entire_computer():
    progress.start()
    threading.Thread(target=scan_entire_computer_and_show_results).start()


def scan_entire_computer_and_show_results():
    results = scan_directory("C:/", virus_database, quarantine_directory, output_file="scan_results.json")
    root.after(0, lambda: show_scan_results(results))


def scan_quarantine():
    progress.start()
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
            else:
                restore_clean_file(file_path, "./restored_files")
                results.append({"file_path": file_path, "hash": file_hash, "status": "Clean and Restored"})
        else:
            results.append({"file_path": file_path, "hash": None, "status": "Error"})
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


# Raporları görüntüleme fonksiyonu
def view_reports():
    try:
        with open("scan_results.json", "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        message = ctk.CTkLabel(root, text="Rapor dosyası bulunamadı.", font=("Poppins", 12))
        message.pack(pady=10)
        return

    report_window = ctk.CTkToplevel(root)
    report_window.title("Tarama Raporları")
    report_window.geometry("600x400")

    # Scrollable Frame
    frame = ctk.CTkScrollableFrame(report_window, width=580, height=350)
    frame.pack(pady=10, padx=10)

    # Rapor içeriği
    for i, item in enumerate(data):
        file_info = f"{i + 1}. {item['file_path']} - {item['status']}"
        label = ctk.CTkLabel(frame, text=file_info, font=("Poppins", 12), anchor="w")
        label.pack(fill="x", pady=2)

    close_button = ctk.CTkButton(report_window, text="Kapat", command=report_window.destroy)
    close_button.pack(pady=10)


# Veritabanı ve dizinleri başlatma
initialize_database()
virus_database = load_virus_database("./VirusHashDB.db")
quarantine_directory = "./quarantine"

# Ana döngü
root.mainloop()