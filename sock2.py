import socket
from pprint import pprint
import threading
import datetime
import asyncio


async def scan(host, port):
    banner = 'empty'
    state = 'c'
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1)
        try:
            data = await asyncio.wait_for(reader.read(100), timeout=1)
            state = 'o'
            try:
                banner = data.decode()
                state = 'o'
                return (port, state, banner)
            except:
                return (port, state, banner)
        except asyncio.TimeoutError:
            state = 'o'
            return (port, state, banner)

    except (ConnectionRefusedError, asyncio.TimeoutError) as e:
        pass


async def gather(host, num_ports):

    try:
        ports_data = await asyncio.gather(*[scan(host, p) for p in range(1, num_ports)], return_exceptions=True)
        ports_data = [p for p in ports_data if isinstance(p, tuple)]
        return ports_data

    except (RuntimeError, ValueError):
        pass


asyncio.run(gather('127.0.0.1', 100))


def report(ports_data, host):
    print(ports_data)
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

    with open('logs2.txt', 'a') as f:
        f.write('\n\n' + 'Host: ' + host)
        f.write('\n\n' + 'Date: ' +
                datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))

        for port in ports_data:
            f.write('\n\n' + 'Port: ' + str(port[0]))
            if port[2] != 'empty':
                f.write('\n\n' + 'Banner' + port[2])
            if port[0] in common_ports:
                f.write('\n\n' + common_ports[port[0]])


print(report(asyncio.run(gather('scanme.nmap.org', 100)), 'scanme.nmap.org'))
