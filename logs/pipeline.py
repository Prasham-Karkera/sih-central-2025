"""
Docstring for pipeline

at the end I want 

#one thread
while running:
    data = listen()
    parsed_data = parser(data)
    database.add(paersed_data)

#main loop 
"""

from scapy.all import ARP, Ether, srp

def scan_network(network="192.168.0.0/24"):
    # Create ARP request  
    arp = ARP(pdst=network)

    # Ethernet broadcast frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Complete ARP packet
    packet = ether / arp

    # Send ARP request → get responses
    result = srp(packet, timeout=2, retry=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices

# Example
for device in scan_network("192.168.0.0/24"):
    print(device)
