# 🛡️ Burmese Digital Store (BDS) Anti-DPI VPN Infrastructure

This standalone repository contains the complete enterprise **Anti-DPI VPN Infrastructure**, 3x-ui Panel configurations, Nginx reverse proxy templates, Cloudflare WARP egress routing, and 1-Click deployment scripts designed to bypass ISP Deep Packet Inspection (DPI) and Great Firewall (GFW) blocking in Myanmar.

---

## 📌 Features

- **Cloudflare CDN Protection (Orange Cloud 🟠):** Proxies `VLESS-WS`, `Trojan-WS`, `VMess-WS`, and `Shadowsocks-WS` traffic through Cloudflare Edge servers (`cdn.bds-node.me`), completely hiding the VPS origin IP from ISP DPI blocking.
- **Cloudflare WARP Outbound (`wireguard` tag):** Automatically routes all CDN user traffic through Cloudflare WARP WireGuard interface (`104.28.222.x` exit IPs), unblocking ChatGPT, OpenAI, Netflix, and preventing Google CAPTCHA triggers.
- **Direct Low-Latency Inbounds:**
  - **`Shadowsocks-Direct` (Port 10005):** `chacha20-ietf-poly1305` fallback for networks that allow direct VPS access.
  - **`VLESS-Reality-Direct` (Port 8443):** Advanced `xtls-rprx-vision` profile for current Xray clients.
- **One subscription per node:** A single client link contains all six inbound profiles with labels based on `SERVER_LABEL` (for example, `SG1 - VLESS WS CDN`). Direct profiles may expose the VPS IP and may be selected by client auto-balancing.
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
│   ├── 04_configure_3xui_db.py           # Idempotent 3x-ui API configurator
│   └── 05_show_subscriptions.py           # Root-only profile viewer and verifier
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

# 2. Create the per-node configuration (never commit node.env)
cp node.env.example node.env
nano node.env

# Set SERVER_LABEL=SG1 (or SG2, SG3, and so on) for this node.
# Install a valid TLS certificate and key at the paths configured in node.env.

# 3. Make deployment scripts executable
chmod +x deploy.sh scripts/*.sh scripts/*.py

# 4. Run or safely re-run the master deployment
sudo ./deploy.sh
```

---

## 📱 Subscription Profile

Each node has one client subscription containing VLESS WS CDN, VMess WS CDN, Trojan WS CDN, Shadowsocks WS CDN, Shadowsocks Direct, and VLESS Reality Direct. Entry names use `SERVER_LABEL`, for example `SG1 - VLESS WS CDN` and `SG1 - VMess WS CDN`. VMess uses `aes-128-gcm` for Hiddify/sing-box and Xray compatibility.

Direct entries may reveal the VPS IP, may be selected by Hiddify auto-balancing, and may be blocked by the user's ISP. Generated subscription credentials are stored only in the root-readable file configured by `SUB_PROFILE_FILE`; they are never committed to this repository. On the VPS, display the single link with:

```bash
sudo bds-dpi-show-subscriptions
```
