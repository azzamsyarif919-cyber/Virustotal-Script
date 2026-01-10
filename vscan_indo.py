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
API_KEY = os.getenv('VT_API_KEY')

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

    # Memosting komentar
def post_comment(url_target, text):
    url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}/comments"
    headers = {"x-apikey": API_KEY, "Content-Type": "application/json"}
    payload = {"data": {"type": "comment", "attributes": {"text": text}}}
    try:
        res = requests.post(api_url, json=payload, headers=headers)
        if res.status_code == 200:
            print(f"{GREEN}[V] Berhasil! Komentar Anda telah dikirim.{RESET}")
        else:
            print(f"{RED}[!] Gagal komen. Kode: {res.status_code}{RESET}")
    except: print(f"{RED}[!] Error koneksi.{RESET}")

    # Menampilkan komentar
def get_comments(url_target):
    url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}/comments?relationships=author"
    headers = {"x-apikey": API_KEY}
    comments_list = []
    try:
        res = requests.get(api_url, headers=headers)
        if res.status_code == 200:
            data = res.json().get('data', [])
            for c in data:
                attr = c['attributes']
                author_data = c.get('relationships', {}).get('author', {}).get('data', {})
                author_name = author_data.get('id', 'Anonymous')
                date = datetime.fromtimestamp(attr['date']).strftime('%Y-%m-%d')
                text = attr['text']
                comments_list.append(f"[{date}] {GREEN}{author_name}{RESET}: {text}")
    except: pass
    return comments_list

    # Tampilan loading
def tampilkan_waktu():
    sekarang = datetime.now()
    waktu_str = sekarang.strftime("%Y-%m-%d | %H:%M:%S")
    quota = get_quota_info()
    print(f"{YELLOW}[ WAKTU: {waktu_str} ] [ KUOTA: {quota} ]{RESET}")

    # Animasi loading
def animasi_cooldown(detik_total):
    print(f"\n{BLUE}[!] Menunggu cooldown API {detik_total}s...{RESET}")
    for i in range(detik_total, -1, -1):
        lebar_layar = shutil.get_terminal_size().columns
        lebar_bar = max(10, lebar_layar - 30)
        persen = int(((detik_total - i) / detik_total) * 100)
        bar = "#" * int(lebar_bar * (persen / 100)) + "-" * (lebar_bar - int(lebar_bar * (persen / 100)))
        sys.stdout.write(f"\r{YELLOW}({i}s) [{bar}] ({persen}%){RESET}")
        sys.stdout.flush()
        if i > 0: time.sleep(1)
    print()

    # Animasi loading
def animasi_loading(durasi, pesan):
    chars = ['/', '-', '\\', '|']
    for i in range(101):
        sys.stdout.write(f'\r{BLUE}{pesan} {chars[i % 4]} {i}%{RESET}')
        sys.stdout.flush()
        time.sleep(durasi / 100)
    print()

def get_real_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except: return url

    # Url yang akan di kirim ke
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
                    threat_details = []
                    for vendor, info in results.items():
                        if info['category'] in ['malicious', 'phishing', 'suspicious']:
                            threat_details.append({
                                'vendor': vendor,
                                'result': info['result'].upper(),
                                'category': info['category']
                            })
                    return attr.get('stats'), threat_details
                time.sleep(2)
    except: return None, []
    return None, []

    # Memperbaiki dan memberi tambahan "https"
def scan_url(url_input):
    if not url_input.startswith(("http://", "https://")):
        url_input = "https://" + url_input

    print(f"\n{YELLOW}[1] Menganalisis Link...{RESET}")
    stats, threats = request_vt_scan_detail(url_input)
    animasi_loading(1, "Memproses Data")

    # Status eror
    if stats is None:
        print(f"{RED}[!] Error: Cek API Key atau Koneksi.{RESET}")
        return False

    real_url = get_real_url(url_input)
    print(f"\n{GREEN}--- HASIL SCAN VENDOR (SAM919🛡️) ---{RESET}")
    print(f"URL Target: {BLUE}{real_url}{RESET}")

    # Deteksi vendor yang di scan
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    print(f"Status: {RED if malicious > 0 else GREEN}{malicious} Malicious | {suspicious} Suspicious{RESET}")

       # Hasil scan dari vendor yang di temukan
    if threats:
        print(f"\n{RED}[!] DETAIL ANCAMAN DITEMUKAN:{RESET}")
        print(f"{'VENDOR':<20} | {'JENIS ANCAMAN (VIRUS)':<20}")
        print("-" * 45)
        for t in threats:
            color = RED if t['category'] == 'malicious' else YELLOW
            print(f"{t['vendor']:<20} | {color}{t['result']:<20}{RESET}")
    else:
        print(f"\n{GREEN}[V] Bersih: Tidak ada vendor yang menandai link ini.{RESET}")

    # Komentar yang di deteksi
    comments = get_comments(real_url)
    print(f"\n{YELLOW}Komentar Komunitas : ({len(comments)}) Komentar ditemukan{RESET}")

    if comments:
        # PERBAIKAN: Enter sekarang dianggap 'y' (Lihat huruf kapital Y)
        lihat = input(f"{BLUE}Lihat detail komentar dari orang lain? (Y/n): {RESET}").strip().lower()
        if lihat in ['y', '']:
            print(f"\n{YELLOW}--- KOMENTAR KOMUNITAS (Global) ---{RESET}")
            for i, comm in enumerate(comments, 1):
                print(f"{i}. {comm}\n{BLUE}{'-'*30}{RESET}")

    # PERBAIKAN: Enter sekarang dianggap 'n' (Sesuai huruf kapital N)
    mau_komen = input(f"\n{GREEN}Tambahkan komentar Anda? (y/N): {RESET}").strip().lower()
    if mau_komen == 'y':
        teks = input(f"{YELLOW}Isi komentar: {RESET}")
        if teks: post_comment(real_url, teks)

    print(f"\n{BLUE}--- ANALISIS SELESAI ---{RESET}")
    return True

def main():
    try:
        while True:
            os.system('clear')
            tampilkan_waktu()
            # Pesan atau menu utama
            print(f"{BLUE}========================================")
            print("    VT-SCANNER V16.0 (ENTER FRIENDLY)   ")
            print("    Dev: SAM919HKSLYOFICIAL01⁺ 🛡️       ")
            print("    Web: Virustotal                     ")
            print(f"========================================{RESET}")

            # Target URL
            target = input(f"\n{GREEN}Masukkan URL untuk di-scan: {RESET}").strip()

            if not target:
                pilihan_keluar = input(f"{RED}[!] URL tidak boleh kosong. Keluar dari program? (y/N): {RESET}").strip().lower()
                if pilihan_keluar == 'y':
                    print(f"\n{GREEN}Stay Safe Kapten. Sampai jumpa!{RESET}")
                    break
                else:
                    continue
            # Pesan url berhasil
            berhasil = scan_url(target)
            if berhasil:
                animasi_cooldown(60)
            else:
                print(f"{YELLOW}\n[!] Scan gagal, cooldown dibatalkan.{RESET}")
                input(f"{BLUE}Tekan Enter untuk lanjut...{RESET}")

            # PERBAIKAN: Enter sekarang dianggap 'y'
            keluar = input(f"\n{BLUE}Lanjut scan lagi? (Y/n): {RESET}").strip().lower()
            if keluar == 'n':
                print(f"\n{GREEN}Stay safe, SAM919!{RESET}")
                break
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] Program dihentikan paksa (Ctrl+C). Keluar...{RESET}")
        sys.exit()

if __name__ == "__main__":
    main()
