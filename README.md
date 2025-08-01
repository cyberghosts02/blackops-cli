<p align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/1/18/ISO_C%2B%2B_Logo.svg" height="100">
</p>

<h1 align="center">🕶️ BLACKOPS-CLI</h1>
<p align="center"><strong>A High-Performance C++ Red Team CLI Suite</strong></p>
<p align="center">Developed by <b>CYBER ALPHA</b> | Team: <b>CYBER GHOSTS</b></p>

---

## 🔥 Overview

**BLACKOPS-CLI** is a powerful Linux-based Red Team command-line suite built in C++ for professional penetration testers, ethical hackers, and cyber operators. With over **20 advanced tools**, it provides real-world offensive and defensive capabilities — all accessible via a blazing-fast binary CLI.

> ⚠️ For **educational and authorized use only**. Always obtain legal permission before testing any network or system.

---

## ✨ Features

╔══════════════════════════════════════════════╗
║ [ Select a Tool ] ║
╠══════════════════════════════════════════════╣
║ [ 1] 🌐 IP Tracer [ 2] 🔍 Subdomain Finder ║
║ [ 3] 🕷 Web Spider [ 4] 💣 DDoS Launcher ║
║ [ 5] 💉 SQLi Auto Exploit [ 6] 🧿 CVE Auto Scanner ║
║ [ 7] 🧩 Username Scanner [ 8] 🔍 Reverse Image Search ║
║ [ 9] 🕵 People Finder [10] 🔐 File Encryptor ║
║[11] 🧹 Anti-Trace Cleaner [12] 🔥 Firewall Manager ║
║[13] 🐚 Shell Uploader [14] 🎭 MAC Changer ║
║[15] 🔍 Port Scanner [16] 📡 Packet Sniffer ║
║[17] 🧰 Wordlist Generator [18] 👁 Hidden File Finder ║
║[19] 🧠 Process Monitor [20] 🪓 Bash Logger ║
║[21] 👤 Developer Info [ 0] ❌ Exit ║
╚══════════════════════════════════════════════╝



---

## 🛠 Installation

### ✅ Supported Platforms
- Kali Linux
- Parrot OS
- Ubuntu / Debian
- Termux (with `proot` and proper dependencies)

### 📦 Dependencies

```bash
sudo apt update
sudo apt install g++ make git libpcap-dev libcurl4-openssl-dev libssl-dev -y
```
#  🔨 Compilation
```
git clone https://github.com/cyberghosts02/blackops-cli.git
cd blackops-cli

g++ -o cyber_alpha alpha.cpp -std=c++17 -lpcap -lcurl -lssl -lcrypto
```
## 🚀 Usage
```
./cyber_alpha
```
*Navigate the menu using number keys 1–21*

*Press 0 to exit*

*Run with sudo for full functionality (network tools, scanners, etc.)*

## 📱 Termux Support 
```
pkg update && pkg upgrade
pkg install clang git openssl curl libpcap
clang++ -o cyber_alpha alpha.cpp -std=c++17 -lpcap -lcurl -lssl -lcrypto
```

### 👨‍💻 Developer Info
```
```   
 👤 Developer: CYBER ALPHA
  
  🧠 Team: CYBER GHOSTS

   💬 Telegram: @cyber_alpha_pk

  📧 Email: alpha-0.2-pk@proton.me

  *Contributions, forks, pull requests, and feedback are always welcome.*
