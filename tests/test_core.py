"""Тесты core: разбор целей, портов, определение доменов."""

import pytest

from reconhunter.core import (
    TOP_PORTS,
    Target,
    is_domain,
    parse_ports,
    parse_target,
)


class TestParseTarget:
    def test_plain_url(self):
        t = parse_target("http://example.com")
        assert t == Target(host="example.com", port=80, scheme="http")
        assert t.is_web and t.base_url == "http://example.com"

    def test_https_custom_port_and_path(self):
        t = parse_target("https://example.com:8443/x/y")
        assert t.port == 8443
        assert t.base_url == "https://example.com:8443"

    def test_host_port(self):
        t = parse_target("scanme.local:3000")
        assert t.host == "scanme.local"
        assert t.port == 3000
        assert not t.is_web

    def test_bare_host(self):
        t = parse_target("example.com")
        assert t.host == "example.com"
        assert t.port is None and t.scheme is None

    def test_bad_scheme(self):
        with pytest.raises(ValueError):
            parse_target("ftp://example.com")

    def test_url_for_port(self):
        t = parse_target("example.com")
        assert t.url_for_port(8080) == "http://example.com:8080"
        assert t.url_for_port(8443) == "https://example.com:8443"


class TestParsePorts:
    def test_top_default(self):
        assert parse_ports("top") == TOP_PORTS
        assert parse_ports("") == TOP_PORTS

    def test_range_and_list(self):
        assert parse_ports("1-5,10") == [1, 2, 3, 4, 5, 10]

    def test_full(self):
        assert len(parse_ports("full")) == 65535

    def test_out_of_range_filtered(self):
        assert parse_ports("0,80,70000") == [80]


class TestIsDomain:
    def test_domain(self):
        assert is_domain("example.com") is True

    def test_ipv4(self):
        assert is_domain("8.8.8.8") is False

    def test_localhost(self):
        assert is_domain("localhost") is False
