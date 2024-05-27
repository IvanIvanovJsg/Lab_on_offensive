from scapy.layers.l2 import ARP, Ether, srp, get_if_addr, get_if_hwaddr
from constants import WIFI_INTERFACE


def get_ip_from_mac(mac_address):
    # Define the broadcast MAC address
    broadcast_mac = "ff:ff:ff:ff:ff:ff"

    # Create an ARP request packet
    arp_request = ARP(
        pdst=f"{get_my_local_ip().rsplit(".", 1)[0]}.0/24"
    )  # Change the network range to match your network
    ether = Ether(dst=broadcast_mac)
    packet = ether / arp_request

    # Send the packet and receive responses
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse the responses
    for sent, received in result:
        if received.hwsrc.lower() == mac_address.lower():
            return received.psrc

    return None


def get_my_local_ip():
    return get_if_addr(WIFI_INTERFACE)


def get_my_mac():
    return get_if_hwaddr(WIFI_INTERFACE)
