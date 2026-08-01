# 🛡️ Burmese Digital Store (BDS) Anti-DPI VPN Infrastructure

This standalone repository contains the complete enterprise **Anti-DPI VPN Infrastructure**, 3x-ui Panel configurations, Nginx reverse proxy templates, Cloudflare WARP egress routing, and 1-Click deployment scripts designed to bypass ISP Deep Packet Inspection (DPI) and Great Firewall (GFW) blocking in Myanmar.

---

## 📌 Features

- **Cloudflare CDN Protection (Orange Cloud 🟠):** Proxies `VLESS-WS`, `Trojan-WS`, `VMess-WS`, and `Shadowsocks-WS` traffic through Cloudflare Edge servers (`cdn.bds-node.me`), completely hiding the VPS origin IP from ISP DPI blocking.
- **Cloudflare WARP Outbound (`wireguard` tag):** Automatically routes all CDN user traffic through Cloudflare WARP WireGuard interface (`104.28.222.x` exit IPs), unblocking ChatGPT, OpenAI, Netflix, and preventing Google CAPTCHA triggers.
- **Direct Low-Latency Inbounds:**
  - **`Shadowsocks-Direct` (Port 10005):** Single-user `chacha20-ietf-poly1305` protocol compatible with Outline App and native clients.
  - **`VLESS-Reality-Direct` (Port 8443):** `xtls-rprx-vision` protocol targeting `www.microsoft.com` SNI.
- **Subdomain & Domain Isolation:** Dedicated VPN domain (`bds-node.me`) separated from primary web applications.
- **Clean IP & TLS Fragmentation Support:** Compatible with Cloudflare Preferred IPs (`104.16.132.229`) and Client TLS Fragmentation to bypass SNI filtering.

---

## 📂 Repository File Structure

```text
.
├── docs/
│   └── DPI_BYPASS_MASTER_GUIDE.md        # Comprehensive Anti-DPI Master Guide (Myanmar)
├── config/
│   └── nginx/
│       └── bds-node.conf                 # Nginx reverse proxy configuration template
├── scripts/
│   ├── 01_setup_bbr.sh                   # Enables Linux BBR congestion control
│   ├── 02_setup_nginx.sh                 # Nginx reverse proxy & SSL installer
│   ├── 03_setup_warp.py                  # Cloudflare WARP WireGuard registrator
│   └── 04_configure_3xui_db.py           # 3x-ui SQLite database configurator
├── deploy.sh                             # 1-Click Master Deployment Script
└── README.md
```

---

## 🚀 Quickstart: 1-Click VPS Deployment

To deploy the entire Anti-DPI VPN infrastructure on a fresh Ubuntu / Debian Linux VPS:

```bash
# 1. Clone this repository on the VPS
git clone https://github.com/blackcoder436-droid/bds-dpi-bypass.git
cd bds-dpi-bypass

# 2. Make deployment scripts executable
chmod +x deploy.sh scripts/*.sh scripts/*.py

# 3. Run master deployment
sudo ./deploy.sh
```

---

## 📱 Active Client Subscription Links

- **3x-ui Native Subscription Link (Hiddify / v2rayNG / V2box / Sing-box):**
  ```text
  https://sub.bds-node.me/1qaa49575uwxf1zx
  ```

- **Outline App Access Key (Direct Shadowsocks):**
  ```text
  ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpjcDd4cGtpa2N0djdxenZz@direct.bds-node.me:10005#Shadowsocks-Direct
  ```
