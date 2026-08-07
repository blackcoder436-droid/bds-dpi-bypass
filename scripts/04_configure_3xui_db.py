#!/usr/bin/env python3
"""
Script 04: 3x-ui Database Auto-Configurator
Configures all inbounds in /etc/x-ui/x-ui.db with production settings:
  - Port 10001: VLESS-WS-CDN
  - Port 10002: VMess-WS-CDN
  - Port 10003: Trojan-WS-CDN
  - Port 10004: Shadowsocks-WS-CDN
  - Port 10005: Shadowsocks-Direct (Single-user chacha20-ietf-poly1305 for Outline App)
  - Port 8443:  VLESS-Reality-Direct (xtls-rprx-vision with www.microsoft.com)
"""

import sqlite3
import json
import subprocess
import time

import sys
import os

def configure_3xui_database():
    db_path = '/etc/x-ui/x-ui.db'
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    client_id = "7526ba13-b0a8-4d30-8ce4-53eb601f23ce"
    client_email = "9xahs2sv7t"
    sub_id = "1qaa49575uwxf1zx"
    password_sec = "cp7xpkikctv7qzvs"
    priv_key = "6DBkzuU5BiTuOPRlDnEXzT79WDNWwsNYL0u5H7r8f24"
    pub_key = "ehNfUkHtzO45nhn9VtDw9iib-KwqZI3n3RM8ZiwCtCE"

    # Domain variables with support for sub1, cdn1, direct1 customization
    cdn_domain = os.environ.get("CDN_DOMAIN", sys.argv[1] if len(sys.argv) > 1 else "cdn1.bds-node.me")
    sub_domain = os.environ.get("SUB_DOMAIN", sys.argv[2] if len(sys.argv) > 2 else "sub1.bds-node.me")
    direct_domain = os.environ.get("DIRECT_DOMAIN", sys.argv[3] if len(sys.argv) > 3 else "direct1.bds-node.me")

    cdn_ext_proxy = [{"dest": cdn_domain, "port": 443, "forceTls": "tls"}]
    direct_ss_ext_proxy = [{"dest": direct_domain, "port": 10005}]
    direct_reality_ext_proxy = [{"dest": direct_domain, "port": 8443}]
    sniffing_config = {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False}

    # Set subPath to "/" in settings table for native sub URL panel compatibility
    cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('subPath', '/');")
    cur.execute(f"INSERT OR REPLACE INTO settings (key, value) VALUES ('subURI', 'https://{sub_domain}/');")

    # 1. VLESS WS CDN (Port 10001)
    vless_ws_settings = {
        "clients": [{"id": client_id, "email": client_email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": 0, "subId": sub_id, "reset": 0}],
        "decryption": "none", "fallbacks": []
    }
    vless_ws_stream = {
        "network": "ws", "security": "none", "externalProxy": cdn_ext_proxy,
        "wsSettings": {"acceptProxyProtocol": False, "host": cdn_domain, "path": "/vless-ws", "headers": {"Host": cdn_domain}}
    }
    cur.execute("UPDATE inbounds SET settings = ?, stream_settings = ?, sniffing = ?, listen = '127.0.0.1', enable = 1 WHERE port = 10001;",
                (json.dumps(vless_ws_settings), json.dumps(vless_ws_stream), json.dumps(sniffing_config)))

    # 2. VMess WS CDN (Port 10002)
    vmess_ws_settings = {
        "clients": [{"id": client_id, "alterId": 0, "email": client_email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": 0, "subId": sub_id, "reset": 0, "security": "auto"}]
    }
    vmess_ws_stream = {
        "network": "ws", "security": "none", "externalProxy": cdn_ext_proxy,
        "wsSettings": {"acceptProxyProtocol": False, "host": cdn_domain, "path": "/vmess-ws", "headers": {"Host": cdn_domain}}
    }
    cur.execute("UPDATE inbounds SET settings = ?, stream_settings = ?, sniffing = ?, listen = '127.0.0.1', enable = 1 WHERE port = 10002;",
                (json.dumps(vmess_ws_settings), json.dumps(vmess_ws_stream), json.dumps(sniffing_config)))

    # 3. Trojan WS CDN (Port 10003)
    trojan_ws_settings = {
        "clients": [{"password": password_sec, "email": client_email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": 0, "subId": sub_id, "reset": 0}]
    }
    trojan_ws_stream = {
        "network": "ws", "security": "none", "externalProxy": cdn_ext_proxy,
        "wsSettings": {"acceptProxyProtocol": False, "host": cdn_domain, "path": "/trojan-ws", "headers": {"Host": cdn_domain}}
    }
    cur.execute("UPDATE inbounds SET settings = ?, stream_settings = ?, sniffing = ?, listen = '127.0.0.1', enable = 1 WHERE port = 10003;",
                (json.dumps(trojan_ws_settings), json.dumps(trojan_ws_stream), json.dumps(sniffing_config)))

    # 4. Shadowsocks WS CDN (Port 10004)
    ss_ws_settings = {
        "method": "chacha20-ietf-poly1305", "password": password_sec, "network": "tcp,udp",
        "clients": [{"method": "chacha20-ietf-poly1305", "password": password_sec, "email": client_email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": 0, "subId": sub_id, "reset": 0}]
    }
    ss_ws_stream = {
        "network": "ws", "security": "none", "externalProxy": cdn_ext_proxy,
        "wsSettings": {"acceptProxyProtocol": False, "host": cdn_domain, "path": "/ss-ws", "headers": {"Host": cdn_domain}}
    }
    cur.execute("UPDATE inbounds SET settings = ?, stream_settings = ?, sniffing = ?, listen = '127.0.0.1', enable = 1 WHERE port = 10004;",
                (json.dumps(ss_ws_settings), json.dumps(ss_ws_stream), json.dumps(sniffing_config)))

    # 5. Shadowsocks Direct (Port 10005) - Single User chacha20-ietf-poly1305 for Outline App compatibility
    ss_direct_settings = {
        "method": "chacha20-ietf-poly1305", "password": password_sec, "network": "tcp,udp", "ivCheck": False
    }
    ss_direct_stream = {
        "network": "tcp", "security": "none", "externalProxy": direct_ss_ext_proxy,
        "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}
    }
    cur.execute("UPDATE inbounds SET settings = ?, stream_settings = ?, sniffing = ?, listen = '0.0.0.0', enable = 1 WHERE port = 10005;",
                (json.dumps(ss_direct_settings), json.dumps(ss_direct_stream), json.dumps(sniffing_config)))

    # 6. VLESS Reality Direct (Port 8443)
    reality_settings = {
        "clients": [{"id": client_id, "flow": "xtls-rprx-vision", "email": client_email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": 0, "subId": sub_id, "reset": 0}],
        "decryption": "none", "fallbacks": []
    }
    reality_stream = {
        "network": "tcp", "security": "reality", "externalProxy": direct_reality_ext_proxy,
        "realitySettings": {
            "show": False, "xver": 0, "dest": "www.microsoft.com:443", "serverNames": ["www.microsoft.com"],
            "privateKey": priv_key, "minClientVer": "", "maxClientVer": "", "maxTimeDiff": 0, "shortIds": ["6ba7b810"]
        },
        "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}
    }
    cur.execute("UPDATE inbounds SET settings = ?, stream_settings = ?, sniffing = ?, listen = '0.0.0.0', enable = 1 WHERE port = 8443;",
                (json.dumps(reality_settings), json.dumps(reality_stream), json.dumps(sniffing_config)))

    conn.commit()
    conn.close()
    print("✓ Successfully configured all 6 inbounds in 3x-ui Database!")
    subprocess.run(['systemctl', 'restart', 'x-ui'])

if __name__ == '__main__':
    configure_3xui_database()
