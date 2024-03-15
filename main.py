import threading
import time
import geoip2.database
import pydivert
import signal

geoip_db_path = 'путь_к_файлу.mmdb'
threshold = 1000
ip_counters = {}
blocked_ips = set()
requests_per_second = 0

reader = geoip2.database.Reader(geoip_db_path)

def get_country(ip_address):
    response = reader.country(ip_address)
    return response.country.iso_code

def reset_counters():
    global ip_counters, requests_per_second
    while True:
        time.sleep(5)
        ip_counters = {}
        requests_per_second = 0

def count_requests():
    global requests_per_second
    while True:
        time.sleep(1)
        print(f"Requests per second: {requests_per_second}")
        requests_per_second = 0
        
reset_thread = threading.Thread(target=reset_counters)
reset_thread.daemon = True
reset_thread.start()

count_thread = threading.Thread(target=count_requests)
count_thread.daemon = True
count_thread.start()

def unblock_ip(ip):
    global blocked_ips
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        print(f"IP {ip} разблокирован")

def signal_handler(sig, frame):
    ip_to_unblock = input("Введите IP для разблокировки: ")
    unblock_ip(ip_to_unblock)

# Обработка сигнала ввода с клавиатуры (Ctrl+C в большинстве систем)
signal.signal(signal.SIGINT, signal_handler)

with pydivert.WinDivert() as w:
    for packet in w:
        src_ip = packet.src_addr
        country = get_country(src_ip)

        if src_ip in blocked_ips:
            continue  # Пропускаем пакеты от заблокированных IP

        if country == 'RU':  
            if src_ip in ip_counters:
                ip_counters[src_ip] += 1  
            else:
                ip_counters[src_ip] = 1  

            if ip_counters[src_ip] > threshold:
                blocked_ips.add(src_ip)

        w.send(packet)
