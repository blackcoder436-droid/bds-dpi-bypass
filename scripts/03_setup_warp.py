#!/usr/bin/env python3
"""
Script 03: Cloudflare WARP Outbound Registrator & Configurator
Registers a WireGuard WARP account via Cloudflare API and configures Xray WireGuard Outbound in /etc/x-ui/x-ui.db
"""

import urllib.request
import json
import sqlite3
import subprocess
import time
import os
import base64

def generate_wireguard_keypair():
    # 1. Try python cryptography module
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        priv = x25519.X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(priv_bytes).decode('utf-8'), base64.b64encode(pub_bytes).decode('utf-8')
    except Exception:
        pass

    # 2. Try wg CLI if available
    try:
        priv_proc = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True)
        priv_key = priv_proc.stdout.strip()
        pub_proc = subprocess.run(['wg', 'pubkey'], input=priv_key, capture_output=True, text=True, check=True)
        pub_key = pub_proc.stdout.strip()
        return priv_key, pub_key
    except Exception:
        pass

    # 3. Try installing wireguard-tools and running wg
    try:
        subprocess.run(['apt-get', 'install', '-y', 'wireguard-tools'], check=True)
        priv_proc = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True)
        priv_key = priv_proc.stdout.strip()
        pub_proc = subprocess.run(['wg', 'pubkey'], input=priv_key, capture_output=True, text=True, check=True)
        pub_key = pub_proc.stdout.strip()
        return priv_key, pub_key
    except Exception as e:
        raise RuntimeError(f"Failed to generate WireGuard keypair: {e}")

def register_warp_account(pub_key):
    url = "https://api.cloudflareclient.com/v0a2158/reg"
    headers = {
        "User-Agent": "okhttp/3.12.1",
        "Content-Type": "application/json; charset=UTF-8"
    }
    payload = {
        "key": pub_key,
        "install_id": "",
        "fcm_token": "",
        "tos": "2024-01-01T00:00:00.000Z",
        "model": "PC",
        "serial_number": "1",
        "locale": "en_US"
    }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req) as response:
        res_data = json.loads(response.read().decode('utf-8'))
        return res_data

def update_xui_warp_config():
    print("=== Registering Cloudflare WARP Account ===")
    my_priv_key, my_pub_key = generate_wireguard_keypair()
    warp_data = register_warp_account(my_pub_key)
    
    account_id = warp_data['id']
    priv_key = my_priv_key
    pub_key = warp_data['config']['peers'][0]['public_key']
    endpoint_addr = warp_data['config']['peers'][0]['endpoint']['host']
    v4_addr = warp_data['config']['interface']['addresses']['v4']
    v6_addr = warp_data['config']['interface']['addresses']['v6']
    reserved = warp_data['config']['client_id']

    db_path = '/etc/x-ui/x-ui.db'
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT value FROM settings WHERE key = 'xrayTemplateConfig';")
    row = cur.fetchone()
    if not row:
        print("❌ Error: xrayTemplateConfig not found in settings!")
        return

    tpl = json.loads(row[0])

    warp_outbound = {
        "protocol": "wireguard",
        "settings": {
            "secretKey": priv_key,
            "address": [v4_addr + "/32", v6_addr + "/128"],
            "peers": [
                {
                    "publicKey": pub_key,
                    "endpoint": endpoint_addr,
                    "allowedIPs": ["0.0.0.0/0", "::/0"]
                }
            ],
            "reserved": list(base64_to_reserved(reserved)),
            "mtu": 1280
        },
        "tag": "warp"
    }

    # Update outbounds in template
    outbounds = [o for o in tpl.get("outbounds", []) if o.get("tag") != "warp"]
    outbounds.append(warp_outbound)
    tpl["outbounds"] = outbounds

    # Update routing rules to direct CDN inbounds to warp
    routing_rules = tpl.get("routing", {}).get("rules", [])
    warp_rule_exists = False
    for rule in routing_rules:
        if rule.get("outboundTag") == "warp":
            rule["inboundTag"] = ["inbound-10001", "inbound-10002", "inbound-10003", "inbound-10004"]
            warp_rule_exists = True
            break
            
    if not warp_rule_exists:
        routing_rules.append({
            "type": "field",
            "inboundTag": ["inbound-10001", "inbound-10002", "inbound-10003", "inbound-10004"],
            "outboundTag": "warp"
        })
    tpl["routing"]["rules"] = routing_rules

    cur.execute("UPDATE settings SET value = ? WHERE key = 'xrayTemplateConfig';", (json.dumps(tpl, indent=2),))
    conn.commit()
    conn.close()
    
    print("✓ Successfully updated Cloudflare WARP Outbound in 3x-ui Database!")
    subprocess.run(['systemctl', 'restart', 'x-ui'])

def base64_to_reserved(res_str):
    import base64
    raw = base64.b64decode(res_str)
    return [int(b) for b in raw]

if __name__ == '__main__':
    update_xui_warp_config()
