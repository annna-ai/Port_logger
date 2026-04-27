import socket
from pprint import pprint
import threading
import datetime


def scan(host, port, ports, lock):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        with s:
            s.connect((host, port))
            try:
                data = s.recv(4096)
                message = data.decode()
                with lock:
                    ports[port] = message
            except TimeoutError:
                with lock:
                    ports[port] = 'o'

    except (ConnectionRefusedError, TimeoutError) as e:
        pass


def threads(host, num_ports):
    ports = {}
    threads = []
    l = threading.Lock()
    for p in range(1, num_ports):
        t = threading.Thread(target=scan, args=(host, p, ports, l))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return ports


def report(ports, host):
    lines = []
    common_ports = {
        20: "FTP (Data Transfer)",
        21: "FTP (Control)",
        22: "SSH (Secure Shell)",
        23: "Telnet",
        25: "SMTP (Email Sending)",
        53: "DNS (Domain Name System)",
        80: "HTTP (Web Traffic)",
        110: "POP3 (Email Retrieval)",
        143: "IMAP (Email Retrieval)",
        443: "HTTPS (Secure Web Traffic)"
    }
    # Create a TCP/IP socket
    ports = dict(sorted(ports.items()))
    for key in ports:
        try:
            lines.append(
                f"Port {key} : {common_ports[int(key)]}")
            if not ports[key] == 'o':
                lines.append(str(ports[key]))

        except KeyError:
            lines.append(f"Port {key}")

    with open('logs.txt', 'a') as f:
        try:
            f.write('\n\n' + 'Host: ' + host)
            f.write('\n\n' + 'Date: ' +
                    datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
            for line in lines:
                f.write('\n\n' + line)
        except Exception as e:
            print(str(e))

    return "\n\n".join(lines)


print(report(threads('scanme.nmap.org', 100), 'scanme.nmap.org'))
