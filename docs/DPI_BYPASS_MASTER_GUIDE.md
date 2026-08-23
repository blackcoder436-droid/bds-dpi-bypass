# 📖 DPI Bypass & Enterprise VPN Infrastructure Master Guide

ဒီ Guide သည် မြန်မာနိုင်ငံ၏ ISP DPI (Deep Packet Inspection) စနစ်များနှင့် တရုတ်နိုင်ငံ၏ GFW (Great Firewall) တို့၏ ပိတ်ဆို့မှုများကို ကျော်လွှားရန်၊ VPS IP Ban ခံရခြင်းမှ ၁၀၀% ကာကွယ်ရန်နှင့် 3x-ui Panel အသုံးပြု၍ Enterprise-Level VPN Service အား ရေရှည် မသေနိုင်အောင် တည်ဆောက်နည်း နည်းပညာရပ်ဆိုင်ရာ မာစတာ လမ်းညွှန်ဖြစ်ပါသည်။

---

## 📌 ၁။ အခြေခံ ဗိသုကာနှင့် သဘောတရား (Core Architecture)

### 1.1 VPS IP Direct Block ခံရခြင်းနှင့် Cloudflare CDN ၏ ကာကွယ်မှု
* **Dedicated IPv4 Address:** VPS စာဗာ ဝယ်ယူပါက သီးသန့် IP (၁) ခုသာ ရရှိမည် ဖြစ်သည်။
* **Direct Connection Risk:** ISP DPI မှ VPS IP ကို တိုက်ရိုက် Block လိုက်ပါက Direct Protocols (Reality / Pure Shadowsocks) လိုင်းများ လုံးဝ ချိတ်ဆက်၍ မရတော့ပါ။
* **Cloudflare CDN Protection (Orange Cloud 🟠):** Cloudflare CDN ဖြတ်ထားပါက User ၏ Traffic သည် VPS IP သို့ တိုက်ရိုက် မသွားဘဲ Cloudflare IP သို့သာ သွားမည်ဖြစ်၍ **ISP ဘက်မှ VPS IP အစစ်ကို မမြင်ရဘဲ IP Ban ခံရခြင်းမှ ၁၀၀% ကာကွယ်ပေးထားပါသည်**။

---

## 🌐 ၂။ Domain Isolation & Subdomain Strategy

ပင်မ စီးပွားရေး Website (`burmesedigital.store`) ပိတ်ဆို့မခံရစေရန်အတွက် **VPN Service အတွက် Dedicated Domain အသစ်တစ်ခု** သီးသန့် သုံးရပါမည်။ (ဥပမာ - `bds-node.me`)

### Subdomain ခွဲခြား သတ်မှတ်ပုံ -
1. **`panel.bds-node.me`** ➡️ 3x-ui Admin Panel ဝင်ရောက်ရန်
2. **`sub.bds-node.me`** ➡️ User များကို Subscription Link ပေးရန် (**Proxied 🟠**)
3. **`cdn.bds-node.me`** ➡️ Cloudflare CDN ခံသုံးမည့် Inbounds များအတွက် (**Proxied 🟠**)
4. **`direct.bds-node.me`** ➡️ Outline compatibility အတွက် ယာယီ Shadowsocks Direct သုံးရန် (**DNS Only ☁️**)

---

## 🔌 ၃။ Protocol, Port & Cloudflare Integration Matrix

Cloudflare CDN (Orange Cloud 🟠) ခံသုံးပါက အောက်ပါ HTTPS Ports များကိုသာ ခွင့်ပြုပါသည် -  
`443`, `2053`, `2083`, `2087`, `2096`

| Service / Protocol | Port | Network/Transport | Cloudflare Proxy Status | Domain / Host Target |
| :--- | :--- | :--- | :--- | :--- |
| **3x-ui Admin Panel** | `2087` (Nginx Proxy) | TCP / HTTPS | **Proxied (Orange 🟠)** | `panel.bds-node.me` |
| **Subscription API** | `2096` (Nginx Proxy) | TCP / HTTPS | **Proxied (Orange 🟠)** | `sub.bds-node.me` |
| **VLESS (CDN)** | `443` (Port 10001) | WebSocket (`ws`) | **Proxied (Orange 🟠)** | Path: `/vless-ws` |
| **VMess (CDN)** | `443` (Port 10002) | WebSocket (`ws`) | **Proxied (Orange 🟠)** | Path: `/vmess-ws` |
| **Trojan (CDN)** | `443` (Port 10003) | WebSocket (`ws`) | **Proxied (Orange 🟠)** | Path: `/trojan-ws` |
| **Shadowsocks Direct** | `10005` | TCP (`chacha20-ietf-poly1305`) | **DNS Only (Gray ☁️)** | `direct.bds-node.me` |

> 💡 **Best Practice Note:** Port `443` တစ်ခုတည်းတွင် Path ကို မတူအောင် ခွဲထုတ်ခြင်း (`/vless-ws`, `/vmess-ws`, `/trojan-ws`, `/ss-ws`) ဖြင့် Cloudflare CDN Inbound များကို အထိရောက်ဆုံး တည်ဆောက်နိုင်ပါသည်။

---

## 🛡️ ၄။ Multi-Layer Anti-DPI Strategy (DPI ကျော်လွှားရေး နည်းဗျူဟာများ)

### 4.1 Server Level Optimization (VPS ဘက်တွင် ပြင်ရန်)
1. **Linux BBR Congestion Control ဖွင့်ခြင်း (Packet Loss လျှော့ချရန်):**
   ```bash
   echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
   echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
   sysctl -p
   ```

2. **Wildcard DNS (`*.bds-node.me`):**
Subdomain အသစ်များကို စက္ကန့်ပိုင်းအတွင်း လဲလှယ်နိုင်ရန် Cloudflare DNS တွင် A Record တည်ဆောက်စဉ် `*` ခံထားပါ။

### 4.2 Cloudflare Edge Level Optimization
1. **SSL/TLS Encryption Mode:** `Full (Strict)` ထားပါ။
2. **Encrypted Client Hello (ECH):** `ON` ပေးပါ။ *(SNI Domain ကို DPI ဖတ်၍ မရအောင် Encryption လုပ်ပေးသည်)*
3. **Minimum TLS Version:** `TLS 1.3` ဟု သတ်မှတ်ပါ။
4. **Protocols:** `WebSockets`၊ `gRPC`၊ `HTTP/2` နှင့် `HTTP/3 (QUIC)` များကို `ON` တင်ထားပါ။

### 4.3 Client App Level Optimization (v2rayNG / NekoBox / Sing-box / Hiddify)
1. **Cloudflare Clean IP (Preferred IP):**
   * Config ၏ `Address` နေရာတွင် ➡️ Cloudflare Clean IP (ဥပမာ - `104.16.132.229` သို့မဟုတ် `104.17.200.1`) ကို ထည့်ပါ။
   * `Host` နှင့် `SNI` နေရာတွင် ➡️ သင့် CDN Domain (`cdn.bds-node.me`) ကိုပင် ဆက်ထားပါ။
2. **TLS Fragment (Packet အပိုင်းပိုင်း ခွဲ၍ ပို့ခြင်း):**
   * DPI မှ TLS ClientHello SNI ကို မဖတ်နိုင်စေရန် App Settings တွင် Fragment ကို **ON** ပါ။
   * **Packets:** `1-3` (သို့မဟုတ် `tlshello`)
   * **Length:** `10-20` (သို့မဟုတ် `100-200`)
   * **Interval:** `10-20` ms

---

## 🚀 ၅။ Cloudflare WARP Outbound Routing (Content & IP Unblocking)

VPS စာဗာပေါ်တွင် **Cloudflare WARP (WireGuard)** ကို Outbound အဖြစ် ချိတ်ဆက်ပေးထားပါသည် -
- WebSocket CDN Nodes များမှ ထွက်သော Traffic အားလုံးသည် WARP Exit IP (`104.28.222.x`) ကို ဖြတ်၍ ပြင်ပသို့ ထွက်ပါသည်။
- OpenAI (ChatGPT), Netflix, Google CAPTCHA တက်ခြင်း များနှင့် IP Ban ခံရခြင်းများအားလုံးကို ၁၀၀% ရှင်းလင်းပေးပါသည်။
