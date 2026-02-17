#!/usr/bin/env bash

# wg-setup - Zero-Knowledge WireGuard Setup Tool
# https://github.com/yourusername/wg-setup

set -o errexit -o nounset -o pipefail
trap 'echo -e "\033[0;31m[ERROR]\033[0m Script failed at line ${LINENO}" >&2; exit 1' ERR

# ============================================================================
# CONSTANTS
# ============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "${0}")"

readonly WG_DIR="/etc/wireguard"
readonly WG_CONFIG="${WG_DIR}/wg0.conf"
readonly WG_PARAMS="${WG_DIR}/params"
readonly WG_INTERFACE="wg0"

readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_RESET='\033[0m'

readonly DEFAULT_IPV4_SUBNET="10.66.66.0/24"
readonly DEFAULT_IPV6_SUBNET="fd42:42:42::0/64"
readonly PORT_RANGE_MIN=49152
readonly PORT_RANGE_MAX=65535

declare -A DNS_PROVIDERS=(
    [1]="Cloudflare:1.1.1.1, 1.0.0.1"
    [2]="Google:8.8.8.8, 8.8.4.4"
    [3]="Quad9:9.9.9.9, 149.112.112.112"
    [4]="OpenDNS:208.67.222.222, 208.67.220.220"
    [5]="AdGuard:94.140.14.14, 94.140.15.15"
    [6]="Mullvad:194.242.2.2, 193.19.108.2"
)

# ============================================================================
# LOGGING
# ============================================================================

log_info()    { echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} ${1}"; }
log_success() { echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} ${1}"; }
log_warning() { echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} ${1}"; }
log_error()   { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} ${1}" >&2; }
log_debug()   { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${COLOR_MAGENTA}[DEBUG]${COLOR_RESET} ${1}" || true; }

# ============================================================================
# VALIDATION
# ============================================================================

validate_public_key() {
    local key="${1}"
    [[ ${#key} -eq 44 && "${key}" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

validate_ipv4() {
    local ip="${1}"
    if [[ "${ip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local -a octets
        IFS='.' read -ra octets <<< "${ip}"
        for octet in "${octets[@]}"; do
            (( octet <= 255 )) || return 1
        done
        return 0
    fi
    return 1
}

validate_port() {
    local port="${1}"
    [[ "${port}" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

validate_client_name() {
    local name="${1}"
    [[ "${name}" =~ ^[a-zA-Z0-9_-]+$ ]]
}

# ============================================================================
# SYSTEM DETECTION
# ============================================================================

detect_os() {
    [[ -e /etc/os-release ]] || { log_error "Unsupported OS"; exit 1; }
    source /etc/os-release
    echo "${ID}"
}

detect_os_version() {
    [[ -e /etc/os-release ]] || return 1
    source /etc/os-release
    echo "${VERSION_ID:-unknown}"
}

get_public_ip() {
    local ip
    local -a services=("https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org")

    for service in "${services[@]}"; do
        if ip=$(curl -s -4 -m 5 "${service}" 2>/dev/null); then
            validate_ipv4 "${ip}" && { echo "${ip}"; return 0; }
        fi
    done

    ip=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    [[ -n "${ip}" ]] && { echo "${ip}"; return 0; }
    return 1
}

get_public_interface() {
    ip -4 route show default | awk '{print $5}' | head -1
}

# ============================================================================
# SYSTEM CHECKS
# ============================================================================

check_root() {
    [[ ${EUID} -eq 0 ]] || { log_error "Run as root: sudo ${SCRIPT_NAME}"; exit 1; }
}

check_os_compat() {
    local os version
    os=$(detect_os)
    version=$(detect_os_version)

    case "${os}" in
        ubuntu) [[ "${version}" < "20.04" ]] && { log_error "Ubuntu 20.04+ required"; exit 1; } ;;
        debian) [[ "${version}" -lt 10 ]] && { log_error "Debian 10+ required"; exit 1; } ;;
        centos|almalinux|rocky) [[ "${version}" -lt 8 ]] && { log_error "${os^} 8+ required"; exit 1; } ;;
        fedora) [[ "${version}" -lt 32 ]] && { log_error "Fedora 32+ required"; exit 1; } ;;
        arch|manjaro) ;;
        *) log_warning "Unsupported OS: ${os}" ;;
    esac
    log_debug "OS: ${os} ${version}"
}

show_install_instructions() {
    local os="${1}"
    case "${os}" in
        ubuntu|debian) echo "  sudo apt update && sudo apt install wireguard wireguard-tools" ;;
        centos|almalinux|rocky|fedora) echo "  sudo dnf install wireguard-tools" ;;
        arch|manjaro) echo "  sudo pacman -S wireguard-tools" ;;
    esac
}

check_wireguard() {
    if ! command -v wg &>/dev/null; then
        log_error "WireGuard not installed"
        show_install_instructions "$(detect_os)"
        exit 1
    fi
}

check_tun() {
    [[ -e /dev/net/tun ]] && ( exec 7<>/dev/net/tun ) 2>/dev/null && exec 7>&- || {
        log_error "TUN device unavailable"
        exit 1
    }
}

# ============================================================================
# NETWORK UTILITIES
# ============================================================================

generate_random_port() { shuf -i "${PORT_RANGE_MIN}-${PORT_RANGE_MAX}" -n 1; }

get_next_available_ip() {
    local subnet="${1}"
    local base_ip=$(echo "${subnet}" | cut -d'/' -f1 | cut -d'.' -f1-3)
    local octet=2

    while grep -q "AllowedIPs.*${base_ip}\.${octet}/32" "${WG_CONFIG}" 2>/dev/null; do
        ((octet++))
        (( octet > 254 )) && { log_error "No available IPs"; exit 1; }
    done

    echo "${base_ip}.${octet}"
}

generate_ipv6_address() {
    local subnet="${1}" last_octet="${2}"
    local base=$(echo "${subnet}" | sed 's/:0\/64//')
    local suffix=$(printf '%x' "${last_octet}")
    echo "${base}:${suffix}"
}

# ============================================================================
# CRYPTOGRAPHY
# ============================================================================

generate_private_key() { wg genkey; }
generate_public_key() { echo "${1}" | wg pubkey; }
generate_preshared_key() { wg genpsk; }

# ============================================================================
# FILE OPERATIONS
# ============================================================================

ensure_directory() {
    local dir="${1}" perms="${2:-755}"
    [[ -d "${dir}" ]] || { mkdir -p "${dir}"; chmod "${perms}" "${dir}"; }
}

write_atomic() {
    local content="${1}" filepath="${2}" perms="${3:-644}"
    local temp=$(mktemp)
    echo "${content}" > "${temp}"
    chmod "${perms}" "${temp}"
    mv "${temp}" "${filepath}"
}

# ============================================================================
# CONFIGURATION
# ============================================================================

load_params() {
    [[ -f "${WG_PARAMS}" ]] || { log_error "Not configured. Run: ${SCRIPT_NAME} install"; exit 1; }
    source "${WG_PARAMS}"
}

save_params() { write_atomic "${1}" "${WG_PARAMS}" "600"; }

# ============================================================================
# SYSTEM CONFIGURATION
# ============================================================================

enable_ip_forwarding() {
    local ipv6="${1:-false}"
    local config="net.ipv4.ip_forward=1"
    [[ "${ipv6}" == "true" ]] && config+=$'\n'"net.ipv6.conf.all.forwarding=1"

    write_atomic "${config}" "/etc/sysctl.d/99-wireguard.conf" "644"
    sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1
    log_success "IP forwarding enabled"
}

disable_ip_forwarding() {
    rm -f /etc/sysctl.d/99-wireguard.conf
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
}

configure_firewall() {
    local port="${1}" subnet="${2}" iface="${3}"

    if command -v firewall-cmd &>/dev/null; then
        log_info "Configuring firewalld..."
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null
        firewall-cmd --permanent --zone=trusted --add-source="${subnet}" >/dev/null
        firewall-cmd --permanent --zone=trusted --add-interface="${iface}" >/dev/null
        firewall-cmd --reload >/dev/null
        log_success "Firewalld configured"
    elif command -v ufw &>/dev/null; then
        log_info "Configuring UFW..."
        ufw allow "${port}/udp" >/dev/null
        log_success "UFW configured"
    fi
}

# ============================================================================
# WIREGUARD SERVICE
# ============================================================================

start_wg() {
    systemctl enable "wg-quick@${1}" >/dev/null 2>&1
    systemctl start "wg-quick@${1}"
    log_success "WireGuard started"
}

stop_wg() {
    systemctl stop "wg-quick@${1}" 2>/dev/null || true
    systemctl disable "wg-quick@${1}" >/dev/null 2>&1 || true
}

reload_wg() {
    if wg syncconf "${1}" <(wg-quick strip "${1}") 2>/dev/null; then
        log_success "Configuration reloaded"
    else
        systemctl restart "wg-quick@${1}"
        log_success "Service restarted"
    fi
}

is_wg_active() { systemctl is-active --quiet "wg-quick@${1}"; }

# ============================================================================
# DNS PROVIDERS
# ============================================================================

show_dns_options() {
    echo -e "${COLOR_CYAN}DNS Providers:${COLOR_RESET}"
    for key in $(echo "${!DNS_PROVIDERS[@]}" | tr ' ' '\n' | sort -n); do
        local info="${DNS_PROVIDERS[${key}]}"
        echo "${key}) ${info%%:*} (${info#*:})"
    done
    echo "7) Custom"
}

get_dns_servers() {
    local choice="${1}"

    if [[ -n "${DNS_PROVIDERS[${choice}]:-}" ]]; then
        echo "${DNS_PROVIDERS[${choice}]#*:}"
    elif [[ "${choice}" == "7" ]]; then
        read -rp "Primary DNS: " dns1
        read -rp "Secondary DNS (optional): " dns2
        echo "${dns1}${dns2:+, ${dns2}}"
    else
        echo "1.1.1.1, 1.0.0.1"
    fi
}

# ============================================================================
# CLIENT MANAGEMENT
# ============================================================================

client_exists() { grep -q "^### Client ${1}$" "${WG_CONFIG}" 2>/dev/null; }
pubkey_exists() { grep -q "PublicKey = ${1}" "${WG_CONFIG}" 2>/dev/null; }
get_client_block() { sed -n "/^### Client ${1}$/,/^$/p" "${WG_CONFIG}"; }

extract_client_info() {
    local name="${1}"
    local block=$(get_client_block "${name}")

    echo -e "ipv4\t$(echo "${block}" | grep "AllowedIPs" | awk '{print $3}' | cut -d',' -f1 | cut -d'/' -f1)"
    echo -e "ipv6\t$(echo "${block}" | grep -oP '([a-f0-9:]+)/128' | cut -d'/' -f1 || echo "")"
    echo -e "pubkey\t$(echo "${block}" | grep "PublicKey" | awk '{print $3}')"
    echo -e "psk\t$(echo "${block}" | grep "PresharedKey" | awk '{print $3}')"
    echo -e "date\t$(echo "${block}" | grep "# Added:" | sed 's/# Added: //')"
}

list_clients() { grep "^### Client" "${WG_CONFIG}" 2>/dev/null | sed 's/### Client //' || true; }

# ============================================================================
# USER INTERACTION
# ============================================================================

prompt_yes_no() {
    local prompt="${1}" default="${2:-n}"
    local response

    if [[ "${default}" == "y" ]]; then
        read -rp "${prompt} [Y/n]: " response
        response=${response:-y}
    else
        read -rp "${prompt} [y/N]: " response
        response=${response:-n}
    fi

    [[ "${response}" =~ ^[Yy]$ ]]
}

prompt_input() {
    local prompt="${1}" default="${2:-}" response

    if [[ -n "${default}" ]]; then
        read -rp "${prompt} [${default}]: " response
        echo "${response:-${default}}"
    else
        read -rp "${prompt}: " response
        echo "${response}"
    fi
}

show_banner() {
    local title="${1}"
    echo -e "${COLOR_GREEN}╔════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    printf "${COLOR_GREEN}║%-60s║${COLOR_RESET}\n" "$(printf '%*s' $(((60+${#title})/2)) "${title}")"
    echo -e "${COLOR_GREEN}╚════════════════════════════════════════════════════════════╝${COLOR_RESET}\n"
}

show_separator() {
    echo -e "${COLOR_GREEN}═══════════════════════════════════════════════════════════${COLOR_RESET}"
}

# ============================================================================
# INSTALLATION
# ============================================================================

install_wireguard_package() {
    if command -v wg &>/dev/null; then
        log_debug "WireGuard already installed"
        return 0
    fi

    log_info "Installing WireGuard..."

    local os=$(detect_os)
    case "${os}" in
        ubuntu|debian)
            apt update -qq || { log_error "apt update failed"; return 1; }
            apt install -y wireguard wireguard-tools || { log_error "Installation failed"; return 1; }
            ;;
        centos|almalinux|rocky|fedora)
            dnf install -y wireguard-tools || { log_error "Installation failed"; return 1; }
            ;;
        arch|manjaro)
            pacman -S --noconfirm wireguard-tools || { log_error "Installation failed"; return 1; }
            ;;
        *)
            log_error "Cannot auto-install on ${os}"
            echo "Install manually:"
            show_install_instructions "${os}"
            return 1
            ;;
    esac

    if ! command -v wg &>/dev/null; then
        log_error "WireGuard installation failed"
        return 1
    fi

    log_success "WireGuard installed"
    return 0
}

install_server() {
    show_banner "WireGuard Server Installation"

    [[ -e "${WG_CONFIG}" ]] && {
        log_warning "Already configured. Use: ${SCRIPT_NAME} add"
        exit 0
    }

    log_info "Starting configuration...\n"

    local srv_ipv4=$(prompt_input "Server IPv4 subnet" "${DEFAULT_IPV4_SUBNET}")
    local srv_ip=$(echo "${srv_ipv4}" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3".1"}')

    local enable_ipv6="false" srv_ipv6="" srv_ip6=""
    if prompt_yes_no "Enable IPv6?"; then
        enable_ipv6="true"
        srv_ipv6=$(prompt_input "Server IPv6 subnet" "${DEFAULT_IPV6_SUBNET}")
        srv_ip6=$(echo "${srv_ipv6}" | sed 's/0\/64/1/')
    fi

    local port=$(prompt_input "WireGuard port" "$(generate_random_port)")
    local endpoint=$(prompt_input "Public IP/hostname" "$(get_public_ip)")
    local pub_iface=$(prompt_input "Public interface" "$(get_public_interface)")

    echo ""
    show_dns_options
    local dns=$(get_dns_servers "$(prompt_input "DNS provider" "1")")

    echo -e "\n${COLOR_CYAN}Routing:${COLOR_RESET}"
    echo "1) Full tunnel (0.0.0.0/0)"
    echo "2) Split tunnel"
    local allowed
    if [[ "$(prompt_input "Select" "1")" == "1" ]]; then
        allowed="0.0.0.0/0${enable_ipv6:+, ::/0}"
    else
        allowed=$(prompt_input "Allowed IPs")
    fi

    echo ""
    install_wireguard_package || exit 1

    log_info "Generating keys..."
    local priv=$(generate_private_key)
    local pub=$(generate_public_key "${priv}")

    enable_ip_forwarding "${enable_ipv6}"

    log_info "Creating configuration..."
    local config="# wg-setup server - $(date +"%Y-%m-%d %H:%M:%S")

[Interface]
Address = ${srv_ip}/24${enable_ipv6:+, ${srv_ip6}/64}
ListenPort = ${port}
PrivateKey = ${priv}

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${pub_iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${pub_iface} -j MASQUERADE"

    [[ "${enable_ipv6}" == "true" ]] && config+="
PostUp = ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${pub_iface} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${pub_iface} -j MASQUERADE"

    ensure_directory "${WG_DIR}" "700"
    write_atomic "${config}" "${WG_CONFIG}" "600"

local params="SERVER_PUB_IP=\"${endpoint}\"
SERVER_PUB_NIC=\"${pub_iface}\"
SERVER_WG_NIC=\"${WG_INTERFACE}\"
SERVER_WG_IPV4=\"${srv_ipv4}\"
SERVER_PORT=\"${port}\"
SERVER_PRIV_KEY=\"${priv}\"
SERVER_PUB_KEY=\"${pub}\"
CLIENT_DNS=\"${dns}\"
ALLOWED_IPS=\"${allowed}\""

[[ "${enable_ipv6}" == "true" ]] && params+="
SERVER_WG_IPV6=\"${srv_ipv6}\""

    save_params "${params}"
    configure_firewall "${port}" "${srv_ipv4}" "${WG_INTERFACE}"
    start_wg "${WG_INTERFACE}"

    echo ""
    show_banner "Installation Complete!"

    echo -e "${COLOR_CYAN}Configuration:${COLOR_RESET}"
    echo -e "  Interface: ${COLOR_GREEN}${WG_INTERFACE}${COLOR_RESET}"
    echo -e "  Address: ${COLOR_GREEN}${srv_ip}/24${COLOR_RESET}"
    [[ "${enable_ipv6}" == "true" ]] && echo -e "  IPv6: ${COLOR_GREEN}${srv_ip6}/64${COLOR_RESET}"
    echo -e "  Port: ${COLOR_GREEN}${port}${COLOR_RESET}"
    echo -e "  Endpoint: ${COLOR_GREEN}${endpoint}:${port}${COLOR_RESET}"

    echo -e "\n${COLOR_YELLOW}Next:${COLOR_RESET} ${COLOR_BLUE}${SCRIPT_NAME} add${COLOR_RESET}"
    echo -e "${COLOR_CYAN}🔐 Server NEVER knows client private keys!${COLOR_RESET}\n"
}

# ============================================================================
# CLIENT OPERATIONS
# ============================================================================

add_client() {
    local name="${1:-}" pubkey="${2:-}"

    show_banner "Add Client"
    load_params

    [[ -z "${name}" ]] && name=$(prompt_input "Client name")
    validate_client_name "${name}" || { log_error "Invalid name (alphanumeric,-,_)"; exit 1; }
    client_exists "${name}" && { log_error "Client '${name}' exists"; exit 1; }

    if [[ -z "${pubkey}" ]]; then
        show_separator
        echo -e "${COLOR_CYAN}🔐 Zero-Knowledge Security${COLOR_RESET}"
        show_separator
        echo -e "\n${COLOR_YELLOW}Client generates keys locally!${COLOR_RESET}"
        echo -e "${COLOR_CYAN}On client: ${COLOR_GREEN}wg genkey | tee privatekey | wg pubkey${COLOR_RESET}\n"
        pubkey=$(prompt_input "Client public key")
    fi

    validate_public_key "${pubkey}" || { log_error "Invalid public key (44 chars base64)"; exit 1; }
    pubkey_exists "${pubkey}" && { log_error "Key already registered"; exit 1; }

    log_info "Generating preshared key..."
    local psk=$(generate_preshared_key)

    local ipv4=$(get_next_available_ip "${SERVER_WG_IPV4}")
    local ipv6=""
    [[ -n "${SERVER_WG_IPV6:-}" ]] && ipv6=$(generate_ipv6_address "${SERVER_WG_IPV6}" "$(echo "${ipv4}" | cut -d'.' -f4)")

    log_info "Adding peer..."
    local peer="

### Client ${name}
# Added: $(date +"%Y-%m-%d %H:%M:%S")
[Peer]
PublicKey = ${pubkey}
PresharedKey = ${psk}
AllowedIPs = ${ipv4}/32${ipv6:+, ${ipv6}/128}"

    echo "${peer}" >> "${WG_CONFIG}"
    reload_wg "${WG_INTERFACE}"

    echo ""
    show_banner "Client Added!"

    echo -e "${COLOR_CYAN}Info:${COLOR_RESET} ${name} → ${COLOR_GREEN}${ipv4}/32${COLOR_RESET}${ipv6:+ ${COLOR_GREEN}${ipv6}/128${COLOR_RESET}}"

    echo ""
    show_separator
    echo -e "${COLOR_GREEN}Client Configuration${COLOR_RESET}"
    show_separator

    local cfg="
[Interface]
# Client: ${name}
# PrivateKey = YOUR_PRIVATE_KEY_HERE
Address = ${ipv4}/32${ipv6:+, ${ipv6}/128}
DNS = ${CLIENT_DNS:-1.1.1.1, 1.0.0.1}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${psk}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25"

    echo "${cfg}"
    echo ""
    show_separator

    echo -e "\n${COLOR_YELLOW}Instructions:${COLOR_RESET}"
    echo "1. Copy config above"
    echo "2. Uncomment PrivateKey line"
    echo "3. Add your private key"
    echo "4. Save as ${name}.conf"

    echo ""
    log_success "Done!\n"
}

remove_client() {
    [[ -f "${WG_CONFIG}" ]] || { log_error "Not configured"; exit 1; }

    show_banner "Remove Client"

    local -a clients
    mapfile -t clients < <(list_clients)

    [[ ${#clients[@]} -eq 0 ]] && { log_warning "No clients"; exit 0; }

    echo -e "${COLOR_CYAN}Clients:${COLOR_RESET}"
    printf '%s\n' "${clients[@]}" | sed 's/^/  • /'

    echo ""
    local name=$(prompt_input "Client to remove")
    client_exists "${name}" || { log_error "Not found"; exit 1; }

    prompt_yes_no "Remove '${name}'?" || { log_info "Cancelled"; exit 0; }

    sed -i "/^### Client ${name}$/,/^$/d" "${WG_CONFIG}"
    reload_wg "${WG_INTERFACE}"

    log_success "Removed '${name}'"
}

list_all() {
    [[ -f "${WG_CONFIG}" ]] || { log_error "Not configured"; exit 1; }

    show_banner "Clients"

    local -a clients
    mapfile -t clients < <(list_clients)

    if [[ ${#clients[@]} -eq 0 ]]; then
        log_warning "No clients"
        echo -e "\n${COLOR_BLUE}Add first: ${SCRIPT_NAME} add${COLOR_RESET}\n"
        exit 0
    fi

    printf "${COLOR_CYAN}%-20s %-20s %-25s %s${COLOR_RESET}\n" "Name" "IPv4" "Public Key" "Added"
    echo "────────────────────────────────────────────────────────────────────────────────────────────"

    for client in "${clients[@]}"; do
        local -A info=()
        while IFS=$'\t' read -r k v; do
            info[${k}]="${v}"
        done < <(extract_client_info "${client}")

        printf "%-20s %-20s %-25s %s\n" \
            "${client}" "${info[ipv4]:-N/A}" "${info[pubkey]:0:22}..." "${info[date]:-N/A}"
    done

    echo ""
    log_success "Total: ${#clients[@]}\n"
}


show_client() {
    local name="${1:-}"

    [[ -f "${WG_CONFIG}" && -f "${WG_PARAMS}" ]] || { log_error "Not configured"; exit 1; }

    [[ -z "${name}" ]] && name=$(prompt_input "Client name")
    load_params
    client_exists "${name}" || { log_error "Not found"; exit 1; }

    local -A info=()
    while IFS=$'\t' read -r k v; do
        info[${k}]="${v}"
    done < <(extract_client_info "${name}")

    show_banner "Client: ${name}"

    echo -e "${COLOR_CYAN}Info:${COLOR_RESET}"
    echo -e "  IPv4: ${COLOR_GREEN}${info[ipv4]:-N/A}/32${COLOR_RESET}"
    [[ -n "${info[ipv6]:-}" ]] && echo -e "  IPv6: ${COLOR_GREEN}${info[ipv6]}/128${COLOR_RESET}"
    echo -e "  PublicKey: ${COLOR_GREEN}${info[pubkey]:-N/A}${COLOR_RESET}"
    echo -e "  Added: ${COLOR_GREEN}${info[date]:-N/A}${COLOR_RESET}"

    echo ""
    show_separator
    echo -e "${COLOR_GREEN}Configuration${COLOR_RESET}"
    show_separator

    cat << EOF

[Interface]
# Client: ${name}
# PrivateKey = YOUR_PRIVATE_KEY
Address = ${info[ipv4]:-N/A}/32${info[ipv6]:+, ${info[ipv6]}/128}
DNS = ${CLIENT_DNS:-1.1.1.1, 1.0.0.1}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${info[psk]:-N/A}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25

EOF
}


uninstall() {
    show_banner "Uninstall"

    echo -e "${COLOR_RED}⚠️  Will remove:${COLOR_RESET}"
    echo "  • WireGuard service"
    echo "  • All configurations"
    echo "  • All client data"
    echo ""

    read -rp "Type 'yes' to confirm: " confirm
    [[ "${confirm}" != "yes" ]] && { log_info "Cancelled"; exit 0; }

    log_info "Stopping service..."
    stop_wg "${WG_INTERFACE}"

    log_info "Removing configs..."
    rm -f "${WG_CONFIG}" "${WG_PARAMS}"

    log_info "Disabling forwarding..."
    disable_ip_forwarding

    log_success "Uninstalled\n"
}

# ============================================================================
# MENU
# ============================================================================

show_menu() {
    echo ""
    show_banner "wg-setup v${SCRIPT_VERSION}"
    echo -e "${COLOR_CYAN}Zero-Knowledge WireGuard Tool${COLOR_RESET}\n"

    if [[ -f "${WG_CONFIG}" ]]; then
        check_wireguard
        echo -e "${COLOR_CYAN}Server:${COLOR_RESET} ${COLOR_GREEN}✓ Configured${COLOR_RESET}"
        is_wg_active "${WG_INTERFACE}" \
            && echo -e "${COLOR_CYAN}Service:${COLOR_RESET} ${COLOR_GREEN}✓ Running${COLOR_RESET}" \
            || echo -e "${COLOR_CYAN}Service:${COLOR_RESET} ${COLOR_RED}✗ Stopped${COLOR_RESET}"

        echo -e "\n1) Add client\n2) Remove client\n3) List clients\n4) Show config\n5) Uninstall\n6) Exit"

        case "$(prompt_input "Option [1-6]")" in
            1) add_client ;;
            2) remove_client ;;
            3) list_all ;;
            4) show_client ;;
            5) uninstall ;;
            6) exit 0 ;;
            *) log_error "Invalid option" && exit 1 ;;
        esac
    else
        echo -e "${COLOR_YELLOW}Server: Not configured${COLOR_RESET}\n"
        echo -e "1) Install server\n2) Exit"

        case "$(prompt_input "Option [1-2]")" in
            1) install_server ;;
            2) exit 0 ;;
            *) log_error "Invalid option" && exit 1 ;;
        esac
    fi
}

show_help() {
    printf "%b\n" \
"${COLOR_GREEN}wg-setup${COLOR_RESET} v${SCRIPT_VERSION} - Zero-Knowledge WireGuard Tool

${COLOR_YELLOW}USAGE:${COLOR_RESET}
  ${SCRIPT_NAME} [COMMAND] [OPTIONS]

${COLOR_YELLOW}COMMANDS:${COLOR_RESET}
  install                  Install WireGuard server
  add [name] [pubkey]      Add client (zero-knowledge)
  remove                   Remove client
  list                     List all clients
  show [name]              Show client config
  uninstall                Remove WireGuard
  version                  Show version
  help                     Show this help

${COLOR_YELLOW}EXAMPLES:${COLOR_RESET}
  ${SCRIPT_NAME}                           # Interactive mode
  ${SCRIPT_NAME} install                   # Install server
  ${SCRIPT_NAME} add laptop \"Ab3Cd...=\"    # Add with key
  ${SCRIPT_NAME} list                      # List clients

${COLOR_YELLOW}CLIENT KEY GENERATION:${COLOR_RESET}
  ${COLOR_CYAN}On client device:${COLOR_RESET}
    wg genkey | tee privatekey | wg pubkey
"
}


# ============================================================================
# MAIN
# ============================================================================

requires_wireguard() {
    local cmd="${1:-}"

    # Команды, которым WireGuard обязателен
    [[ "${cmd}" =~ ^(add|remove|list|show|uninstall)$ ]] && return 0

    return 1
}


main() {
    check_root
    check_os_compat
    check_tun

    local cmd="${1:-}"
    requires_wireguard "${cmd}" && check_wireguard

    case "${cmd}" in
        install) install_server ;;
        add) add_client "${2:-}" "${3:-}" ;;
        remove) remove_client ;;
        list) list_all ;;
        show) show_client "${2:-}" ;;
        uninstall) uninstall ;;
        version|--version|-v) echo "wg-setup v${SCRIPT_VERSION}" ;;
        help|--help|-h) show_help ;;
        "") show_menu ;;
        *) log_error "Unknown: ${1}"; echo "Use: ${SCRIPT_NAME} help"; exit 1 ;;
    esac
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
