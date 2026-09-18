#!/bin/bash
# =============================================================================
# network_audit.sh: VPN & DNS Network Security Audit Tool
# Author: Hunter Franklin
#
# Tests:
#   1) DNS Leak Check    -- plaintext UDP 53 on physical interface
#  1b) IPv6 DNS Check    -- plaintext IPv6 UDP 53 on physical interface
#   2) DoH Verification  -- DNS routing through encrypted DoH
#   3) VPN Integrity     -- traffic bypassing the WireGuard tunnel (noise filtered)
#   4) Encrypted View    -- WireGuard envelopes on physical interface
#   5) Decrypted View    -- plaintext traffic inside tunnel
#   6) Process Hunt      -- process owning a suspicious port
#   7) Public IP Check   -- query external edge via curl
#   8) Run All           -- tests sequentially + summary
#   9) Install Aliases   -- shortcuts to ~/.zshrc
# =============================================================================

# -----------------------------------------------------------------------------
PHYSICAL_INTERFACE="en0"    # en0=WiFi, en1=Ethernet
WIREGUARD_PORT="51820"      # NordLynx default
DOH_SERVER="1.1.1.1"        # Cloudflare DoH
SEQUENTIAL_DURATION=10      # Seconds per test in Run All
AUTO_DETECT_PHYSICAL=true
AUTO_DETECT_TUNNEL=true
# -----------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

VERDICT_DNS="" VERDICT_DOH="" VERDICT_VPN="" VERDICT_ENC="" VERDICT_DEC=""
export VERDICT_DNS VERDICT_DOH VERDICT_VPN VERDICT_ENC VERDICT_DEC


get_physical_interface() {
    if [ "$AUTO_DETECT_PHYSICAL" = true ]; then
        IFACE=$(route get default 2>/dev/null | grep interface | awk '{print $2}')
        if [ -z "$IFACE" ] || [[ "$IFACE" == utun* ]]; then
            echo "$PHYSICAL_INTERFACE"
        else
            echo "$IFACE"
        fi
    else
        echo "$PHYSICAL_INTERFACE"
    fi
}


get_tunnel_interface() {
    if [ "$AUTO_DETECT_TUNNEL" = true ]; then
        TUNNEL=$(ifconfig 2>/dev/null | awk '
            /^utun/ { iface = substr($1, 1, length($1)-1) }
            /inet .* -->/ && iface { print iface; iface="" }
        ' | head -1)
        if [ -z "$TUNNEL" ]; then
            TUNNEL=$(ifconfig 2>/dev/null | awk '
                /^utun/ { iface = substr($1, 1, length($1)-1) }
                /inet / && iface && ($2 ~ /^10\./ || $2 ~ /^192\.168\./ || $2 ~ /^100\./) {
                    print iface; iface=""
                }
            ' | head -1)
        fi
        echo "${TUNNEL:-utun0}"
    else
        echo "utun0"
    fi
}


print_header() {
    PHYS=$(get_physical_interface)
    TUNNEL=$(get_tunnel_interface)
    echo ""
    echo -e "${CYAN}${BOLD}================================================${NC}"
    echo -e "${CYAN}${BOLD}      VPN & DNS Network Security Auditor${NC}"
    echo -e "${CYAN}        github.com/HunterBFranklin${NC}"
    echo -e "${CYAN}${BOLD}================================================${NC}"
    echo -e "  Physical : ${GREEN}${BOLD}$PHYS${NC}      WireGuard port $WIREGUARD_PORT"
    echo -e "  Tunnel   : ${GREEN}${BOLD}$TUNNEL${NC}    DoH $DOH_SERVER"
    echo -e "${CYAN}${BOLD}================================================${NC}"
    echo ""
}


print_menu() {
    echo -e "${BOLD}${YELLOW}Select a test:${NC}"
    echo ""
    echo -e "  ${CYAN}Encrypted ($PHYS)${NC}"
    echo "  1) DNS Leak Check    -- IPv4 UDP 53 plaintext should be zero"
    echo " 1b) IPv6 DNS Check    -- IPv6 UDP 53 plaintext should be zero"
    echo "  2) DoH Verification  -- confirm DNS routing to $DOH_SERVER"
    echo "  3) VPN Integrity     -- detect traffic bypassing WireGuard (mDNS filtered)"
    echo "  4) Encrypted View    -- raw WireGuard envelopes on $PHYS"
    echo ""
    echo -e "  ${CYAN}Decrypted ($TUNNEL) & External${NC}"
    echo "  5) Decrypted View    -- plaintext traffic inside tunnel"
    echo "  6) Process Hunt      -- identify process owning a port"
    echo "  7) Public IP Check   -- query external edge via curl"
    echo ""
    echo -e "  ${CYAN}Bulk${NC}"
    echo "  8) Run All           -- core tests sequentially + summary"
    echo "  9) Install Aliases   -- write shortcuts to ~/.zshrc"
    echo "  q) Quit"
    echo ""
    read -rp "Choice: " choice
}


check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        echo -e "${YELLOW}[*] sudo required for tcpdump...${NC}"
        sudo -v || { echo -e "${RED}[!] sudo required. Exiting.${NC}"; exit 1; }
    fi
}


timed_tcpdump() {
    local OUTFILE="$1"
    local DURATION="$2"
    shift 2
    local PCAPFILE
    PCAPFILE=$(mktemp -t na_pcap)

    sudo tcpdump "$@" -w "$PCAPFILE" 2>>"$OUTFILE" &
    local TCPDUMP_PID=$!

    sleep "$DURATION"
    sudo kill -SIGINT "$TCPDUMP_PID" 2>/dev/null
    wait "$TCPDUMP_PID" 2>/dev/null

    if [ -f "$PCAPFILE" ]; then
        sudo tcpdump -r "$PCAPFILE" -n -q 2>/dev/null | tee -a "$OUTFILE" >/dev/null
    fi

    rm -f "$PCAPFILE"
}


get_packet_count() {
    echo "$1" | grep "packets captured" | awk '{print $1}'
}


print_verdict() {
    local STATUS="$1" HEADLINE="$2" NOTE="$3"
    echo ""
    echo -e "${BOLD}------------------------------------------------${NC}"
    case "$STATUS" in
        PASS) echo -e "  ${GREEN}${BOLD}[ PASS ]${NC}  $HEADLINE" ;;
        FAIL) echo -e "  ${RED}${BOLD}[ FAIL ]${NC}  $HEADLINE" ;;
        WARN) echo -e "  ${YELLOW}${BOLD}[ WARN ]${NC}  $HEADLINE" ;;
        INFO) echo -e "  ${CYAN}${BOLD}[ INFO ]${NC}  $HEADLINE" ;;
    esac
    [ -n "$NOTE" ] && echo -e "           $NOTE"
    echo -e "${BOLD}------------------------------------------------${NC}"
    echo ""
}


evaluate_dns_leak() {
    local COUNT
    COUNT=$(get_packet_count "$1")
    if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
        VERDICT_DNS="PASS"
        print_verdict "PASS" "No plaintext DNS detected." \
            "UDP 53 is clean on $PHYS -- DNS is encrypted."
    else
        VERDICT_DNS="FAIL"
        print_verdict "FAIL" "Plaintext DNS detected ($COUNT packets)." \
            "UDP 53 visible on $PHYS -- check VPN DNS leak protection."
    fi
}


evaluate_doh() {
    local COUNT HTTPS_COUNT
    COUNT=$(get_packet_count "$1")
    HTTPS_COUNT=$(echo "$1" | grep -c "443")
    if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
        VERDICT_DOH="WARN"
        print_verdict "WARN" "No traffic to $DOH_SERVER on $PHYS." \
            "DoH is likely routing inside the tunnel -- this is expected and ideal."
    elif [ "$HTTPS_COUNT" -gt 0 ]; then
        VERDICT_DOH="PASS"
        print_verdict "PASS" "DoH confirmed to $DOH_SERVER:443." \
            "DNS is encrypted via HTTPS on $PHYS."
    else
        VERDICT_DOH="WARN"
        print_verdict "WARN" "Traffic to $DOH_SERVER but not on port 443." \
            "Verify DoH is configured correctly."
    fi
}


evaluate_vpn_integrity() {
    local COUNT UNEXPECTED
    COUNT=$(get_packet_count "$1")
    UNEXPECTED=$(echo "$1" \
        | grep -v " port 67\| port 68\| port 5353\| port 1900" \
        | grep -c "IP ")
    if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
        VERDICT_VPN="PASS"
        print_verdict "PASS" "No traffic outside WireGuard tunnel." \
            "All traffic on $PHYS is inside UDP $WIREGUARD_PORT."
    elif [ "$UNEXPECTED" -gt 0 ]; then
        VERDICT_VPN="FAIL"
        print_verdict "FAIL" "$UNEXPECTED unexpected packets outside tunnel." \
            "Non-WireGuard traffic on $PHYS -- possible VPN leak. Use Test 6."
    else
        VERDICT_VPN="PASS"
        print_verdict "PASS" "Only LAN broadcast/discovery traffic outside tunnel." \
            "DHCP/mDNS/SSDP only -- no leak detected."
    fi
}


evaluate_encrypted_view() {
    local COUNT
    COUNT=$(get_packet_count "$1")
    if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
        VERDICT_ENC="WARN"
        print_verdict "WARN" "No WireGuard traffic on $PHYS." \
            "VPN may not be connected. Check UDP $WIREGUARD_PORT."
    else
        VERDICT_ENC="PASS"
        print_verdict "PASS" "WireGuard active -- $COUNT encrypted packets." \
            "Tunnel confirmed on $PHYS:$WIREGUARD_PORT."
    fi
}


evaluate_decrypted_view() {
    local COUNT HTTPS_COUNT
    COUNT=$(get_packet_count "$1")
    HTTPS_COUNT=$(echo "$1" | grep -c "\.443 \|port 443")
    if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
        VERDICT_DEC="WARN"
        print_verdict "WARN" "No traffic on tunnel interface $TUNNEL." \
            "Tunnel may be inactive. Run ifconfig to check active utun interfaces."
    else
        VERDICT_DEC="INFO"
        print_verdict "INFO" "$COUNT packets on $TUNNEL ($HTTPS_COUNT HTTPS)." \
            "Real IPs visible here -- all encrypted before reaching $PHYS."
    fi
}


run_dns_leak() {
    local IFACE DURATION OUTFILE RESULT
    IFACE=$(get_physical_interface)
    DURATION="${1:-$SEQUENTIAL_DURATION}"
    OUTFILE=$(mktemp -t na_txt)
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 1] IPv4 DNS Leak Check${NC}"
    echo -e "  Interface : ${GREEN}$IFACE${NC} (physical)"
    echo -e "  Filter    : udp port 53"
    echo -e "  Expect    : zero packets -- all DNS should be encrypted"
    echo ""
    timed_tcpdump "$OUTFILE" "$DURATION" -i "$IFACE" -n udp port 53
    RESULT=$(cat "$OUTFILE"); rm -f "$OUTFILE"
    echo "$RESULT"
    evaluate_dns_leak "$RESULT"
}


run_ipv6_dns_leak() {
    local IFACE DURATION OUTFILE RESULT COUNT
    IFACE=$(get_physical_interface)
    DURATION="${1:-$SEQUENTIAL_DURATION}"
    OUTFILE=$(mktemp -t na_txt)
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 1b] IPv6 DNS Leak Check${NC}"
    echo -e "  Interface : ${GREEN}$IFACE${NC} (physical)"
    echo -e "  Filter    : ip6 and udp port 53"
    echo -e "  Expect    : zero packets -- IPv6 DNS should be tunneled"
    echo ""
    timed_tcpdump "$OUTFILE" "$DURATION" -i "$IFACE" -n ip6 and udp port 53
    RESULT=$(cat "$OUTFILE"); rm -f "$OUTFILE"
    echo "$RESULT"
    COUNT=$(get_packet_count "$RESULT")
    if [ "$COUNT" = "0" ] || [ -z "$COUNT" ]; then
        print_verdict "PASS" "No plaintext IPv6 DNS detected." "IPv6 UDP 53 is clean on $PHYS."
    else
        print_verdict "FAIL" "Plaintext IPv6 DNS detected ($COUNT packets)." "Check IPv6 leak protections."
    fi
}


run_doh_check() {
    local IFACE DURATION OUTFILE RESULT
    IFACE=$(get_physical_interface)
    DURATION="${1:-$SEQUENTIAL_DURATION}"
    OUTFILE=$(mktemp -t na_txt)
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 2] DoH Verification${NC}"
    echo -e "  Interface : ${GREEN}$IFACE${NC} (physical)"
    echo -e "  Filter    : host $DOH_SERVER"
    echo -e "  Expect    : HTTPS (port 443) traffic -- DoH wraps DNS in TLS"
    echo ""
    timed_tcpdump "$OUTFILE" "$DURATION" -i "$IFACE" -n host "$DOH_SERVER"
    RESULT=$(cat "$OUTFILE"); rm -f "$OUTFILE"
    echo "$RESULT"
    evaluate_doh "$RESULT"
}


run_vpn_integrity() {
    local IFACE DURATION OUTFILE RESULT WG_ENDPOINT
    IFACE=$(get_physical_interface)
    DURATION="${1:-$SEQUENTIAL_DURATION}"
    OUTFILE=$(mktemp -t na_txt)
    WIREGUARD_ENDPOINT=$(sudo wg show all endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1 | head -1)
    local FILTER="not udp port $WIREGUARD_PORT and not port 5353 and not port 1900 and not broadcast"
    if [[ -n "$WG_ENDPOINT" ]]; then
        FILTER="$FILTER and not host $WG_ENDPOINT"
    fi
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 3] VPN Integrity${NC}"
    echo -e "  Interface : ${GREEN}$IFACE${NC} (physical)"
    echo -e "  Filter    : $FILTER"
    echo -e "  Expect    : near silence -- all internet traffic inside WireGuard"
    if [[ -n "$WG_ENDPOINT" ]]; then
        echo -e "  WG Endpoint: ${GREEN}$WG_ENDPOINT${NC} (excluded from leak check)"
    fi
    echo ""
    timed_tcpdump "$OUTFILE" "$DURATION" -i "$IFACE" -n "$FILTER"
    RESULT=$(cat "$OUTFILE"); rm -f "$OUTFILE"
    echo "$RESULT"
    evaluate_vpn_integrity "$RESULT"
}


run_encrypted_view() {
    local IFACE DURATION OUTFILE RESULT
    IFACE=$(get_physical_interface)
    DURATION="${1:-$SEQUENTIAL_DURATION}"
    OUTFILE=$(mktemp -t na_txt)
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 4] Encrypted View${NC}"
    echo -e "  Interface : ${GREEN}$IFACE${NC} (physical)"
    echo -e "  Filter    : udp port $WIREGUARD_PORT"
    echo -e "  Expect    : encrypted WireGuard envelopes only"
    echo ""
    timed_tcpdump "$OUTFILE" "$DURATION" -i "$IFACE" -n -v udp port "$WIREGUARD_PORT"
    RESULT=$(cat "$OUTFILE"); rm -f "$OUTFILE"
    echo "$RESULT"
    evaluate_encrypted_view "$RESULT"
}


run_decrypted_view() {
    local TUNNEL DURATION OUTFILE RESULT
    TUNNEL=$(get_tunnel_interface)
    DURATION="${1:-$SEQUENTIAL_DURATION}"
    OUTFILE=$(mktemp -t na_txt)
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 5] Decrypted View${NC}"
    echo -e "  Interface : ${GREEN}$TUNNEL${NC} (tunnel)"
    echo -e "  Filter    : all traffic"
    echo -e "  Expect    : real IPs and protocols -- TLS content still encrypted"
    echo ""
    timed_tcpdump "$OUTFILE" "$DURATION" -i "$TUNNEL" -n -tttt
    RESULT=$(cat "$OUTFILE"); rm -f "$OUTFILE"
    echo "$RESULT"
    evaluate_decrypted_view "$RESULT"
}


run_process_hunt() {
    local TUNNEL OUTFILE LSOF_RESULT NETSTAT_RESULT TRAFFIC PROCESS PID
    TUNNEL=$(get_tunnel_interface)
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 6] Process Hunt${NC}"
    echo -e "  Interface : ${GREEN}$TUNNEL${NC} (tunnel)"
    echo -e "  Action    : identify process owning a suspicious port"
    echo ""
    read -rp "  Port: " PORT

    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        echo -e "${RED}[!] Invalid port.${NC}"; return
    fi

    echo ""
    LSOF_RESULT=$(lsof -i :"$PORT" 2>/dev/null)
    [ -n "$LSOF_RESULT" ] && echo "$LSOF_RESULT" || echo "  No process on port $PORT."

    echo ""
    NETSTAT_RESULT=$(netstat -an 2>/dev/null | grep "\.$PORT ")
    [ -n "$NETSTAT_RESULT" ] && echo "$NETSTAT_RESULT" || echo "  No active connections."

    echo ""
    echo -e "${YELLOW}Live capture on $TUNNEL -- 10s...${NC}"
    echo ""
    OUTFILE=$(mktemp -t na_txt)
    timed_tcpdump "$OUTFILE" 10 -i "$TUNNEL" -n port "$PORT"
    TRAFFIC=$(cat "$OUTFILE"); rm -f "$OUTFILE"
    echo "$TRAFFIC"

    echo ""
    echo -e "${BOLD}------------------------------------------------${NC}"
    if [ -n "$LSOF_RESULT" ]; then
        PROCESS=$(echo "$LSOF_RESULT" | awk 'NR==2{print $1}')
        PID=$(echo "$LSOF_RESULT" | awk 'NR==2{print $2}')
        echo -e "  ${GREEN}${BOLD}[ RESULT ]${NC}  $PROCESS (PID $PID) owns port $PORT"
    else
        echo -e "  ${YELLOW}${BOLD}[ RESULT ]${NC}  No process bound to port $PORT."
    fi
    echo -e "${BOLD}------------------------------------------------${NC}"
    echo ""
}


run_public_ip_check() {
    echo ""
    echo -e "${CYAN}${BOLD}[TEST 7] Public IP & Edge Check${NC}"
    echo -e "  Action    : querying external edge via curl..."
    echo ""
    if command -v curl &>/dev/null; then
        curl -s https://cloudflare.com/cdn-cgi/trace | grep -E "ip=|loc=|asn="
    else
        echo -e "${RED}[!] curl not found.${NC}"
    fi
    echo ""
}


print_summary() {
    echo ""
    echo -e "${CYAN}${BOLD}================================================${NC}"
    echo -e "${CYAN}${BOLD}                AUDIT SUMMARY${NC}"
    echo -e "${CYAN}${BOLD}================================================${NC}"
    echo ""
    for TEST in "DNS Leak (IPv4):VERDICT_DNS" "DoH Verify:VERDICT_DOH" \
                "VPN Integrity:VERDICT_VPN" "Encrypted View:VERDICT_ENC" \
                "Decrypted View:VERDICT_DEC"; do
        NAME="${TEST%%:*}"; VAR="${TEST##*:}"; STATUS="${!VAR}"
        case "$STATUS" in
            PASS) echo -e "  ${GREEN}${BOLD}[PASS]${NC}  $NAME" ;;
            FAIL) echo -e "  ${RED}${BOLD}[FAIL]${NC}  $NAME" ;;
            WARN) echo -e "  ${YELLOW}${BOLD}[WARN]${NC}  $NAME" ;;
            INFO) echo -e "  ${CYAN}${BOLD}[INFO]${NC}  $NAME" ;;
            *)    echo -e "  ${YELLOW}${BOLD}[SKIP]${NC}  $NAME" ;;
        esac
    done
    echo ""
    if [[ "$VERDICT_DNS" == "FAIL" || "$VERDICT_VPN" == "FAIL" ]]; then
        echo -e "  ${RED}${BOLD}Overall: ACTION REQUIRED${NC}"
    elif [[ "$VERDICT_DNS" == "WARN" || "$VERDICT_VPN" == "WARN" ]]; then
        echo -e "  ${YELLOW}${BOLD}Overall: REVIEW RECOMMENDED${NC}"
    else
        echo -e "  ${GREEN}${BOLD}Overall: CLEAN${NC}"
    fi
    echo ""
    echo -e "${CYAN}${BOLD}================================================${NC}"
    echo ""
}


run_all() {
    PHYS=$(get_physical_interface)
    TUNNEL=$(get_tunnel_interface)
    VERDICT_DNS="" VERDICT_DOH="" VERDICT_VPN="" VERDICT_ENC="" VERDICT_DEC=""
    echo ""
    echo -e "${CYAN}${BOLD}[ALL TESTS] ${SEQUENTIAL_DURATION}s per test${NC}"
    echo "================================================"
    run_dns_leak "$SEQUENTIAL_DURATION"
    run_ipv6_dns_leak "$SEQUENTIAL_DURATION"
    run_doh_check "$SEQUENTIAL_DURATION"
    run_vpn_integrity "$SEQUENTIAL_DURATION"
    run_encrypted_view "$SEQUENTIAL_DURATION"
    run_decrypted_view "$SEQUENTIAL_DURATION"
    run_public_ip_check
    print_summary
}


install_aliases() {
    local ZSHRC="$HOME/.zshrc"
    local PHYS TUNNEL
    PHYS=$(get_physical_interface); TUNNEL=$(get_tunnel_interface)

    if grep -q "network_audit aliases" "$ZSHRC" 2>/dev/null; then
        echo -e "${YELLOW}[!] Aliases already exist in $ZSHRC.${NC}"; return
    fi

    cat >> "$ZSHRC" << EOF

# ---- network_audit aliases -- github.com/HunterBFranklin/network-audit ----
alias dns-leak='sudo tcpdump -i $PHYS -n udp port 53'
alias ipv6-dns-leak='sudo tcpdump -i $PHYS -n ip6 and udp port 53'
alias doh-check='sudo tcpdump -i $PHYS -n host $DOH_SERVER'
alias vpn-integrity='sudo tcpdump -i $PHYS -n "not udp port $WIREGUARD_PORT and not port 5353 and not port 1900 and not broadcast"'
alias wg-view='sudo tcpdump -i $PHYS -n -v udp port $WIREGUARD_PORT'
alias tunnel-view='sudo tcpdump -i $TUNNEL -n -tttt'
alias public-ip='curl -s https://cloudflare.com/cdn-cgi/trace | grep -E "ip=|loc=|asn="'
# ---------------------------------------------------------------------------
EOF

    echo -e "${GREEN}[+] Aliases written to $ZSHRC${NC}"
    echo -e "${YELLOW}    Run: source ~/.zshrc${NC}"
}


PHYS=$(get_physical_interface)
TUNNEL=$(get_tunnel_interface)

print_header
check_sudo

while true; do
    print_menu
    case $choice in
        1) run_dns_leak ;;
        1b|1B) run_ipv6_dns_leak ;;
        2) run_doh_check ;;
        3) run_vpn_integrity ;;
        4) run_encrypted_view ;;
        5) run_decrypted_view ;;
        6) run_process_hunt ;;
        7) run_public_ip_check ;;
        8) run_all ;;
        9) install_aliases ;;
        q|Q) echo "Exiting."; exit 0 ;;
        *) echo -e "${RED}[!] Invalid choice.${NC}" ;;
    esac
    echo ""
    read -rp "Run another test? (y/n): " again
    [[ "$again" != "y" ]] && break
done