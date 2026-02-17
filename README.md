# wg-setup

**Zero-Knowledge WireGuard VPN Setup Tool**

Secure, user-friendly bash script for WireGuard VPN servers. The server **never** knows client private keys.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![WireGuard](https://img.shields.io/badge/WireGuard-compatible-orange.svg)](https://www.wireguard.com/)



## Features

- **Zero-Knowledge** - Server never sees client private keys
- **Post-Quantum PSK** - Pre-shared keys for quantum resistance
- **Auto-Install** - Automated WireGuard package installation
- **IPv4 + IPv6** - Dual-stack support



## Requirements

| OS                     | Min Version |     | OS           | Min Version |
| ---------------------- | ----------- | --- | ------------ | ----------- |
| Ubuntu                 | 20.04+      |     | Fedora       | 32+         |
| Debian                 | 10+         |     | Arch/Manjaro | Any         |
| CentOS/AlmaLinux/Rocky | 8+          |     |              |             |



## Quick Start

```bash
# Download
wget https://raw.githubusercontent.com/kreash/wg-setup/main/wg-setup.sh
chmod +x wg-setup.sh

# Install server
sudo ./wg-setup.sh install

# Add client
sudo ./wg-setup.sh add
```



## Usage

### Interactive Mode

```bash
sudo ./wg-setup.sh
```

### Commands

| Command               | Description                 |
| --------------------- | --------------------------- |
| `install`             | Install WireGuard server    |
| `add [name] [pubkey]` | Add client (zero-knowledge) |
| `remove`              | Remove client               |
| `list`                | List all clients            |
| `show [name]`         | Show client configuration   |
| `uninstall`           | Remove WireGuard completely |
| `version`             | Show version                |
| `help`                | Show help                   |

### Client Key Generation

```bash
# On client device, run:
wg genkey | tee privatekey | wg pubkey
```

Copy the **public key** (stdout) to the server. Keep **privatekey** file secret!


## Acknowledgments

Inspired by:

- [Nyr/wireguard-install](https://github.com/Nyr/wireguard-install)
- [angristan/wireguard-install](https://github.com/angristan/wireguard-install)



## 📜 License

MIT License - see [LICENSE](LICENSE) file.

⭐ **Star this project if you find it useful!**
