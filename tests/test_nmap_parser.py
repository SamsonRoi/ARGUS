from argus.modules.nmap_parser import (
    describe_reason,
    get_scanner_version,
    hosts_from_scanner,
)


def test_reads_basic_host_details(fake_scanner):
    scanner = fake_scanner(
        hosts={
            "192.168.1.10": {
                "hostnames": [{"name": "printer.lan", "type": "PTR"}],
                "addresses": {"ipv4": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},
                "vendor": {"AA:BB:CC:DD:EE:FF": "Acme Devices"},
                "status": {"state": "up", "reason": "arp-response"},
            }
        }
    )

    host = hosts_from_scanner(scanner)[0]

    assert host.ip == "192.168.1.10"
    assert host.state == "up"
    assert host.hostname == "printer.lan"
    assert host.mac == "AA:BB:CC:DD:EE:FF"
    assert host.vendor == "Acme Devices"
    assert host.discovery_method == "ARP reply"


def test_empty_strings_become_none(fake_scanner):
    scanner = fake_scanner(
        hosts={
            "10.0.0.1": {
                "hostnames": [{"name": "", "type": ""}],
                "addresses": {"ipv4": "10.0.0.1"},
                "vendor": {},
                "status": {"state": "up", "reason": ""},
                "tcp": {
                    80: {
                        "state": "open",
                        "name": "",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                    }
                },
            }
        }
    )

    host = hosts_from_scanner(scanner)[0]
    port = host.ports[0]

    assert host.hostname is None
    assert host.mac is None
    assert host.discovery_method is None
    assert port.service is None
    assert port.product is None
    assert port.version is None
    assert port.extra_info is None


def test_reads_tcp_and_udp_ports(fake_scanner):
    scanner = fake_scanner(
        hosts={
            "10.0.0.1": {
                "status": {"state": "up", "reason": "user-set"},
                "tcp": {
                    "22": {
                        "state": "open",
                        "name": "ssh",
                        "product": "OpenSSH",
                        "version": "8.9p1",
                        "extrainfo": "protocol 2.0",
                    }
                },
                "udp": {161: {"state": "open|filtered", "name": "snmp"}},
            }
        }
    )

    host = hosts_from_scanner(scanner)[0]

    assert len(host.ports) == 2
    assert [port.port for port in host.open_ports] == [22]

    ssh = host.open_ports[0]
    assert ssh.service == "ssh"
    assert ssh.version_text == "OpenSSH 8.9p1"
    assert ssh.extra_info == "protocol 2.0"

    snmp = [port for port in host.ports if port.protocol == "udp"][0]
    assert snmp.state == "open|filtered"


def test_malformed_port_is_skipped(fake_scanner):
    scanner = fake_scanner(
        hosts={
            "10.0.0.1": {
                "status": {"state": "up"},
                "tcp": {
                    "not-a-number": {"state": "open"},
                    99999: {"state": "open"},
                    443: {"state": "open"},
                },
            }
        }
    )

    host = hosts_from_scanner(scanner)[0]

    assert [port.port for port in host.ports] == [443]


def test_user_set_reason_claims_no_discovery_method():
    assert describe_reason("user-set") is None
    assert describe_reason("") is None
    assert describe_reason(None) is None


def test_unknown_reason_is_passed_through():
    assert describe_reason("something-new") == "something-new"
    assert describe_reason("echo-reply") == "ICMP echo reply"


def test_best_os_guess_is_chosen(fake_scanner):
    scanner = fake_scanner(
        hosts={
            "10.0.0.1": {
                "status": {"state": "up"},
                "osmatch": [
                    {"name": "Linux 3.2", "accuracy": "90"},
                    {"name": "Linux 5.4", "accuracy": "97"},
                    {"name": "Broken entry", "accuracy": "n/a"},
                    {"name": "", "accuracy": "100"},
                ],
            }
        }
    )

    guess = hosts_from_scanner(scanner)[0].os_guess

    assert guess.name == "Linux 5.4"
    assert guess.accuracy == 97


def test_no_os_information_gives_no_guess(fake_scanner):
    scanner = fake_scanner(hosts={"10.0.0.1": {"status": {"state": "up"}}})

    assert hosts_from_scanner(scanner)[0].os_guess is None


def test_scanner_with_no_hosts(fake_scanner):
    assert hosts_from_scanner(fake_scanner()) == []


def test_scanner_version(fake_scanner):
    assert get_scanner_version(fake_scanner(version=(7, 993))) == "7.993"
    assert get_scanner_version(object()) is None