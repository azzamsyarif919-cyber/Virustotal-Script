#setelah di lihat ambil script ini dan masukkan key anda.

import requests
import os
import time
import sys
import base64
import shutil
from datetime import datetime

# --- KONFIGURASI WARNA ---
BLUE = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'
YELLOW = '\033[93m'

# Ambil API KEY dari Environment
API_KEY =  #masukkan key di sini

def get_quota_info():
    api_url = f"https://www.virustotal.com/api/v3/users/{API_KEY}/overall_quotas"
    headers = {"x-apikey": API_KEY}
    try:
        res = requests.get(api_url, headers=headers)
        if res.status_code == 200:
            daily = res.json()['data'].get('api_requests_daily', {}).get('user', {})
            return f"{daily.get('used', 0)}/{daily.get('allowed', 500)}"
    except: pass
    return "???"

def tampilkan_waktu():
    sekarang = datetime.now()
    waktu_str = sekarang.strftime("%Y-%m-%d | %H:%M:%S")
    quota = get_quota_info()
    print(f"{YELLOW}[ WAKTU: {waktu_str} ] [ KUOTA: {quota} ]{RESET}")

def animasi_cooldown(detik_total):
    # Pesan pembuka cooldown (Bisa kamu edit di bawah ini)
    print(f"\n{BLUE}[!] Menunda 60 detik demi keamanan API agar tidak terblokir...{RESET}")

    for i in range(detik_total, -1, -1):
        lebar_layar = shutil.get_terminal_size().columns
        lebar_bar = max(10, lebar_layar - 30)

        persen = int(((detik_total - i) / detik_total) * 100)
        isi_bar = int(lebar_bar * (persen / 100))
        bar = "#" * isi_bar + "-" * (lebar_bar - isi_bar)

        sys.stdout.write(f"\r{YELLOW}({i}s) Proses:[{bar}] ({persen}%){RESET}")
        sys.stdout.flush()
        if i > 0:
            time.sleep(1)

    print(f"\n{GREEN}[V] Selesai! Kamu bisa melakukan scan lagi sekarang.{RESET}")

def animasi_loading(durasi, pesan):
    chars = ['/', '-', '\\', '|']
    for i in range(101):
        char = chars[i % len(chars)]
        sys.stdout.write(f'\r{BLUE}{pesan} {char} {i}%{RESET}')
        sys.stdout.flush()
        time.sleep(durasi / 100)
    print()

def get_real_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except: return url

def get_comments(url_target):
    url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}/comments"
    headers = {"x-apikey": API_KEY}
    comments_list = []
    try:
        res = requests.get(api_url, headers=headers)
        if res.status_code == 200:
            for c in res.json().get('data', []):
                attr = c['attributes']
                date = datetime.fromtimestamp(attr['date']).strftime('%Y-%m-%d')
                comments_list.append(f"[{date}] {attr['text']}")
    except: pass
    return comments_list

def request_vt_scan_detail(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": API_KEY}
    payload = {"url": url}
    try:
        response = requests.post(api_url, data=payload, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            while True:
                report_res = requests.get(report_url, headers=headers).json()
                attr = report_res['data'].get('attributes', {})
                if attr.get('status') == 'completed':
                    results = attr.get('results', {})
                    vendors_detected = [f"{n} ({d['result']})" for n, d in results.items() if d['category'] in ['malicious', 'phishing']]
                    return attr.get('stats'), vendors_detected
                time.sleep(2)
    except: return None, []
    return None, []

def scan_url(url_input):
    if not url_input.startswith(("http://", "https://")):
        url_input = "https://" + url_input

    print(f"\n{YELLOW}[1] STEP 1: Analisis Link Pendek...{RESET}")
    stats_awal, vendors_awal = request_vt_scan_detail(url_input)
    animasi_loading(1, "Memindai")

    if stats_awal is None:
        print(f"{RED}[!] Error: API Limit tercapai atau koneksi terputus.{RESET}")
        return

    print(f"\n{YELLOW}[2] STEP 2: Melacak Link Asli...{RESET}")
    real_url = get_real_url(url_input)

    if real_url != url_input:
        print(f"{BLUE}[!] Redirect Ditemukan: {real_url}{RESET}")
        animasi_loading(2, "Menganalisis Link Tujuan")
        stats_akhir, vendors_akhir = request_vt_scan_detail(real_url)
        if not stats_akhir: stats_akhir, vendors_akhir = stats_awal, vendors_awal
    else:
        stats_akhir, vendors_akhir = stats_awal, vendors_awal

    comments = get_comments(real_url)

    print(f"\n{GREEN}--- LAPORAN DETAIL SAM919🛡️ ---{RESET}")
    print(f"Target Utama       : {BLUE}{real_url}{RESET}")
    malicious = stats_akhir.get('malicious', 0)
    print(f"Total Bahaya       : {RED}{malicious}{RESET}")
    print(f"Komentar Komunitas : {YELLOW}({len(comments)}) Komentar{RESET}")

    if vendors_akhir:
        print(f"\n{RED}[!] Vendor yang Mendeteksi:{RESET}")
        for v in vendors_akhir: print(f"  - {v}")

    if comments:
        pilihan = input(f"\n{BLUE}Lihat detail komentar? (Y/n): {RESET}").strip().lower()
        if pilihan in ['y', '']:
            print(f"\n{YELLOW}--- KOMENTAR KOMUNITAS ---{RESET}")
            for i, comm in enumerate(comments, 1): print(f"{i}. {comm}\n{'-'*20}")

    print(f"\n{BLUE}--- KESIMPULAN ---{RESET}")
    if malicious > 0:
        print(f"{RED}[!!!] LINK BERBAHAYA!{RESET}")
        #os.system("termux-vibrate -d 1000")
        #os.system("termux-notification -t '🚨 SAM919 DETECTED' -c 'Bahaya!'")
    else: print(f"{GREEN}[V] Aman. Tidak ada vendor yang menandai link ini.{RESET}")

def main():
    while True:
        os.system('clear')
        tampilkan_waktu()
        print(f"{BLUE}========================================")
        print(f"    PRO VT-SCANNER V12.2 (POLISHED)     ")
        print(f"    Cybersecurity-by-SAM919🛡️           ")
        print(f"{GREEN}    SCANED WITH VIRUSTOTAL")
        print(f"========================================{RESET}")

        target = input(f"\n{GREEN}Masukkan URL: {RESET}")
        if target:
            scan_url(target)
            animasi_cooldown(60)
        else:
            print(f"{RED}URL tidak boleh kosong!{RESET}")

        print(f"\n{YELLOW}----------------------------------------{RESET}")
        # Pesan konfirmasi keluar sesuai permintaan
        keluar = input(f"{BLUE}Mau keluar? Pilih 'y' untuk keluar, lanjut pilih 'n' atau Enter: {RESET}").strip().lower()
        if keluar == 'y':
            print(f"\n{GREEN}Terima kasih, SAM919. Stay Safe!{RESET}")
            break

if __name__ == "__main__":
    main()
