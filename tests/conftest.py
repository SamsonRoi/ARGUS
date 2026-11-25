"""Shared test helpers (pytest loads this file automatically)."""

import socket
import threading
import time

import pytest


class FakeScanner:
    """Stands in for python-nmap's PortScanner, so tests need no real scan.

    It offers only the parts that ARGUS reads.
    """

    def __init__(self, hosts=None, version=(7, 99)):
        self._hosts = hosts or {}
        self._version = version

    def all_hosts(self):
        return list(self._hosts)

    def __getitem__(self, ip):
        return self._hosts[ip]

    def nmap_version(self):
        return self._version


@pytest.fixture
def fake_scanner():
    """Gives a test the FakeScanner class."""
    return FakeScanner


@pytest.fixture
def listening_port():
    """Open one TCP port on this computer (127.0.0.1) and return its number."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))  # port 0 = "pick any free port"
    server.listen(5)

    yield server.getsockname()[1]

    server.close()


@pytest.fixture
def ssh_banner_port():
    """Open a TCP port that announces itself like an OpenSSH server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(50)

    def talk(connection):
        try:
            connection.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
            time.sleep(0.2)
        except OSError:
            pass
        finally:
            connection.close()

    def serve():
        while True:
            try:
                connection, _ = server.accept()
            except OSError:
                return

            # One thread per connection: Nmap may open several at once.
            threading.Thread(target=talk, args=(connection,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()

    yield server.getsockname()[1]

    server.close()