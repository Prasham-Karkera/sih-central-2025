schema

📄 Zeek conn.log Schema
Field	Meaning
ts	Timestamp when connection was seen (epoch / human format in some logs)
uid	Unique ID for the connection used to correlate across logs
id.orig_h	Source IP address
id.orig_p	Source port
id.resp_h	Destination IP address
id.resp_p	Destination port
proto	Transport layer protocol (tcp / udp / icmp)
service	Detected application protocol (http, dns, ssl, ssh, — if unknown)
duration	Duration of the connection (seconds)
orig_bytes	Bytes sent by originator
resp_bytes	Bytes sent by responder
conn_state	State of the connection (S0, S1, SF, REJ, SH, etc.)
local_orig	Whether originator is local (T/F or − if unknown)
missed_bytes	# of missed bytes during capture
history	Packet exchange sequence (e.g. ShADadF)
orig_pkts	Packets sent by originator
orig_ip_bytes	IP-level bytes from originator
resp_pkts	Packets sent by responder
resp_ip_bytes	IP-level bytes from responder
tunnel_parents	If connection was encapsulated (VPN, GRE etc., usually (empty))