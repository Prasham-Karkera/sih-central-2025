from src.parsers.ngnix_parser import NginxParser

p = NginxParser()
line = '192.168.1.100 - - [06/Dec/2025:04:17:07 +0000] "GET /api/test HTTP/1.1" 200 1234'

print(f"Line: {line}")
print(f"Can parse: {p.can_parse(line)}")
parsed = p.parse(line)
print(f"Parsed: {parsed}")
