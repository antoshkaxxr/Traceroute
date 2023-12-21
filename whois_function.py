import socket


def whois_func(ip):
    addr = "whois.ripe.net" if ':' in ip else "whois.arin.net"
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM) if ':' in ip \
        else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((addr, 43))
    query = f"n {ip}\r\n".encode("utf-8")
    sock.send(query)

    response = b""
    while True:
        data = sock.recv(4096)
        response += data
        if not data:
            break
    sock.close()

    lines = response.decode("utf-8").splitlines()
    for line in lines:
        if line.startswith("OriginAS"):
            info = line.split(':')
            if 'AS' in info[-1]:
                return info[-1].strip()

    return '-'
