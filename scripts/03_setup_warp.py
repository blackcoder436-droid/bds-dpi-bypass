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

def register_warp_account():
    url = "https://api.cloudflareclient.com/v0a2158/reg"
    headers = {
        "User-Agent": "okhttp/3.12.1",
        "Content-Type": "application/json; charset=UTF-8"
    }
    req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
    with urllib.request.urlopen(req) as response:
        res_data = json.loads(response.read().decode('utf-8'))
        return res_data

def update_xui_warp_config():
    print("=== Registering Cloudflare WARP Account ===")
    warp_data = register_warp_account()
    
    account_id = warp_data['id']
    priv_key = warp_data['config']['peers'][0]['secret_key']
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
