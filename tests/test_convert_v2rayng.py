import base64
import json
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from convert_v2rayng import share_link


class ShareLinkTests(unittest.TestCase):
    def test_vless_reality_and_websocket(self):
        proxy = {
            "type": "vless", "name": "测试 1", "server": "example.org", "port": 443,
            "uuid": "abc-123", "tls": True, "network": "ws", "servername": "sni.example.org",
            "reality-opts": {"public-key": "public-key", "short-id": "01"},
            "ws-opts": {"path": "/ws?ed=2048", "headers": {"Host": "host.example.org"}},
        }
        url = urlsplit(share_link(proxy))
        params = parse_qs(url.query)
        self.assertEqual(url.scheme, "vless")
        self.assertEqual(params["security"], ["reality"])
        self.assertEqual(params["pbk"], ["public-key"])
        self.assertEqual(params["sid"], ["01"])
        self.assertEqual(params["path"], ["/ws?ed=2048"])
        self.assertEqual(unquote(url.fragment), "测试 1")

    def test_shadowsocks_sip002(self):
        url = share_link({"type": "ss", "name": "node", "server": "example.org", "port": 443,
                          "cipher": "aes-128-gcm", "password": "a:b"})
        userinfo = urlsplit(url).netloc.split("@", 1)[0]
        decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        self.assertEqual(decoded, "aes-128-gcm:a:b")

    def test_vmess_payload(self):
        url = share_link({"type": "vmess", "name": "node", "server": "example.org", "port": 443,
                          "uuid": "uuid", "network": "ws", "tls": True,
                          "ws-opts": {"headers": {"Host": "cdn.example.org"}, "path": "/ws"}})
        payload = json.loads(base64.b64decode(url.removeprefix("vmess://")))
        self.assertEqual((payload["net"], payload["host"], payload["path"], payload["tls"]),
                         ("ws", "cdn.example.org", "/ws", "tls"))

    def test_trojan_defaults_to_tls(self):
        url = share_link({"type": "trojan", "name": "node", "server": "example.org", "port": 443,
                          "password": "secret"})
        self.assertEqual(parse_qs(urlsplit(url).query)["security"], ["tls"])

    def test_unsupported_nodes_are_skipped(self):
        self.assertIsNone(share_link({"type": "http", "name": "node", "server": "example.org", "port": 80}))
        self.assertIsNone(share_link({"type": "ss", "name": "node", "server": "example.org", "port": 443,
                                      "cipher": "2022-blake3-chacha20-poly1305", "password": "secret"}))


if __name__ == "__main__":
    unittest.main()
