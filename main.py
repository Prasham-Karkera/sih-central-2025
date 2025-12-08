import socket
import os



UDP_IP = "0.0.0.0"       # listen on all interfaces
UDP_PORT = 5140

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"[*] Syslog UDP server listening on port {UDP_PORT}")

try:
    os.makedirs("./logs", exist_ok=True)
    with open("./logs/syslog_messages.log", "a", encoding="utf-8") as logfile:
        while True:
            data, addr = sock.recvfrom(65535)
            message = f"[{addr[0]}] {data.decode(errors='ignore')}\n"
            print(message, end="")
            logfile.write(message)
            logfile.flush()
except KeyboardInterrupt:
    print("\n[!] Exiting on user request (Ctrl+C)")
finally:
    sock.close()
