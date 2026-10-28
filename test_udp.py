"""Exercise multiple DNS queries over a single SOCKS5 UDP association."""

from __future__ import annotations

import os
import socket
import time
from typing import Protocol

import dns.exception
import dns.message
import dns.rdatatype
import socks


class DatagramSocket(Protocol):
    """Minimal datagram-socket surface used by this probe."""

    def sendto(self, data: bytes, address: tuple[str, int]) -> int: ...

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]: ...

    def settimeout(self, timeout: float | None, /) -> None: ...

    def close(self) -> None: ...


def create_dns_query(domain: str) -> bytes:
    """Build a DNS A-record query."""
    return dns.message.make_query(domain, "A").to_wire()


def send_dns_query(
    sock: DatagramSocket,
    domain: str,
    dns_server: tuple[str, int] = ("8.8.8.8", 53),
) -> bool:
    """Send one DNS query and report whether an A-record response arrived."""
    print(f"\n🔍 Querying {domain} via {dns_server[0]}...")
    try:
        sock.sendto(create_dns_query(domain), dns_server)
        sock.settimeout(5.0)
        data, address = sock.recvfrom(1024)
    except TimeoutError:
        print(f"❌ Timeout querying {domain}")
        return False
    except OSError as error:
        print(f"❌ Socket error querying {domain}: {error}")
        return False

    try:
        response = dns.message.from_wire(data)
    except dns.exception.DNSException as error:
        print(f"❌ Invalid DNS response for {domain}: {error}")
        return False

    addresses = [
        str(item)
        for answer in response.answer
        for item in answer.items
        if item.rdtype == dns.rdatatype.A
    ]
    print(f"✅ Response from {address}:")
    if addresses:
        print(f"   IP Addresses: {', '.join(addresses)}")
    else:
        print("   No A records found")
    return True


def configure_proxy(sock: socks.socksocket) -> None:
    """Apply SOCKS5 proxy settings from the environment."""
    host = os.getenv("SOCKS_HOST", "localhost")
    port = int(os.getenv("SOCKS_PORT", "1080"))
    username = os.getenv("SOCKS_USERNAME")
    password = os.getenv("SOCKS_PASSWORD")

    print(f"🔗 Using SOCKS5 proxy: {host}:{port}")
    if username:
        print(f"🔐 Authentication: {username}")
    else:
        print("🔓 No authentication (anonymous)")

    sock.setproxy(
        socks.SOCKS5,
        host,
        port,
        rdns=True,
        username=username,
        password=password,
    )


def run_queries(sock: DatagramSocket) -> int:
    """Run the fixed DNS probe set over one association."""
    domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "python.org",
        "rust-lang.org",
    ]
    dns_servers = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 53),
        ("8.8.4.4", 53),
    ]

    print(f"🚀 Sending {len(domains)} DNS queries through the same SOCKS pipe...")
    print("=" * 60)
    successful = 0
    for index, domain in enumerate(domains, 1):
        print(f"\n[{index}/{len(domains)}]", end=" ")
        dns_server = dns_servers[index % len(dns_servers)]
        successful += send_dns_query(sock, domain, dns_server)
        if index < len(domains):
            time.sleep(0.5)

    print("\n" + "=" * 60)
    print(f"✨ Completed: {successful}/{len(domains)} queries successful")
    print("💡 All queries used the same SOCKS5 UDP association!")
    return successful


def main() -> None:
    """Create one SOCKS5 UDP association and run the DNS probe set."""
    sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        configure_proxy(sock)
        print("\n📡 Establishing SOCKS5 UDP association...")
        run_queries(sock)
    except OSError as error:
        print(f"❌ Connection error: {error}")
    finally:
        print("\n🔒 Closing SOCKS connection...")
        sock.close()


if __name__ == "__main__":
    main()
