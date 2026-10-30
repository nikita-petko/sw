#!/usr/bin/env bash
# Sets up (and tears down) a gateway between two interfaces: IPv4 forwarding, NAT, an address for the LAN
# side and optionally a DHCP server, turning this host into the router lagsw's `forward: true` profiles expect.
#
# usage: scripts/setup_gateway.sh up     --wan eth0 --lan wlan0 [--lan-address 192.168.50.1/24] [--dhcp]
#                                        [--dns 1.1.1.1,8.8.8.8] [--no-nat] [--ipv6] [--dry-run]
#        scripts/setup_gateway.sh down   [--ipv6] [--dry-run]
#        scripts/setup_gateway.sh status
#
#   --wan IFACE          upstream interface (e.g. eth0): LAN traffic is forwarded out of it and masqueraded
#   --lan IFACE          downstream interface (e.g. wlan0): clients behind it are allowed to use the WAN
#   --lan-address CIDR   address and prefix to give --lan (this host becomes the clients' gateway). Defaults
#                        to the IPv4 address already on --lan; required if it has none
#   --dhcp               run a DHCP server (dnsmasq) on --lan; without it, clients need the static
#                        settings that `up` and `status` print (address, netmask, gateway, DNS)
#   --dns LIST           comma-separated DNS servers handed to DHCP clients (default 1.1.1.1,8.8.8.8)
#   --no-nat             forward only; do not masquerade (the upstream router must route the LAN subnet)
#   --ipv6               also configure ip6tables and net.ipv6.conf.all.forwarding (no DHCPv6/RA)
#   --dry-run            print the commands instead of running them
#
# All rules live in their own LAGSW_* chains, so `down` removes exactly what `up` added, and `up` can be
# repeated safely. `down` also stops the DHCP server, removes an address that `up` assigned, and restores
# the previous ip_forward sysctl values.
set -euo pipefail

FWD_CHAIN="LAGSW_FWD"
NAT_CHAIN="LAGSW_NAT"
IN_CHAIN="LAGSW_IN"
STATE_FILE="${LAGSW_GATEWAY_STATE:-/run/lagsw-gateway.state}"
DHCP_PID="${STATE_FILE%.state}.dhcp.pid"
DHCP_LEASES="${STATE_FILE%.state}.dhcp.leases"
DEFAULT_DNS="1.1.1.1,8.8.8.8"

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit "${1:-1}"; }
die() { echo "error: $*" >&2; exit 1; }

cmd="${1:-}"; [ $# -gt 0 ] && shift
wan="" lan="" lan_cidr_arg="" dns="" nat=1 v6=0 dry=0 dhcp=0
while [ $# -gt 0 ]; do
    case "$1" in
        --wan) [ $# -ge 2 ] || die "--wan needs an interface"; wan="$2"; shift 2 ;;
        --lan) [ $# -ge 2 ] || die "--lan needs an interface"; lan="$2"; shift 2 ;;
        --lan-address) [ $# -ge 2 ] || die "--lan-address needs ADDRESS/PREFIX"; lan_cidr_arg="$2"; shift 2 ;;
        --dns) [ $# -ge 2 ] || die "--dns needs a comma-separated list"; dns="$2"; shift 2 ;;
        --dhcp) dhcp=1; shift ;;
        --no-nat) nat=0; shift ;;
        --ipv6) v6=1; shift ;;
        --dry-run) dry=1; shift ;;
        -h|--help) usage 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

run() { if [ "$dry" = 1 ]; then echo "+ $*"; else "$@"; fi; }
quiet() { if [ "$dry" = 1 ]; then echo "+ $*"; else "$@" 2>/dev/null; fi; }

tables() { if [ "$1" = 6 ]; then echo ip6tables; else echo iptables; fi; }
versions() { if [ "$v6" = 1 ]; then echo "4 6"; else echo 4; fi; }

need_root() { [ "$dry" = 1 ] || [ "$EUID" -eq 0 ] || die "must run as root (try: sudo $0 $cmd ...)"; }
need_tool() { command -v "$1" >/dev/null 2>&1 || [ "$dry" = 1 ] || die "$1 not found"; }
need_iface() { [ "$dry" = 1 ] || ip link show dev "$1" >/dev/null 2>&1 || die "interface '$1' does not exist"; }
sysctl_get() { sysctl -n "$1" 2>/dev/null || echo ""; }

# ---- IPv4 arithmetic (pure bash) ----
ip2int() { local IFS=.; set -- $1; echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )); }
int2ip() { echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"; }

# Parses ADDRESS/PREFIX into gw_ip, prefix, mask, net_int, bcast_int.
parse_cidr() {
    local cidr="$1" o
    [[ "$cidr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$ ]] \
        || die "invalid address '$cidr' (expected ADDRESS/PREFIX, e.g. 192.168.50.1/24)"
    for o in 1 2 3 4; do [ "${BASH_REMATCH[$o]}" -le 255 ] || die "invalid address '$cidr'"; done
    gw_ip="${cidr%/*}"; prefix="${BASH_REMATCH[5]}"
    { [ "$prefix" -ge 8 ] && [ "$prefix" -le 30 ]; } || die "prefix /$prefix is unsupported (use /8 to /30)"
    local mask_int=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    mask="$(int2ip "$mask_int")"
    net_int=$(( $(ip2int "$gw_ip") & mask_int ))
    bcast_int=$(( net_int | (~mask_int & 0xFFFFFFFF) ))
    [ "$(ip2int "$gw_ip")" -ne "$net_int" ] && [ "$(ip2int "$gw_ip")" -ne "$bcast_int" ] \
        || die "'$cidr' is the network or broadcast address of its subnet"
}

# Computes dhcp_start/dhcp_end for the parsed subnet, leaving the gateway address out of the pool.
dhcp_pool() {
    local usable=$(( bcast_int - net_int - 1 ))
    if [ "$usable" -ge 200 ]; then
        dhcp_start=$(( net_int + 100 )); dhcp_end=$(( net_int + 199 ))
    else
        dhcp_start=$(( net_int + 1 )); dhcp_end=$(( bcast_int - 1 ))
    fi
    local gw; gw="$(ip2int "$gw_ip")"
    if [ "$gw" -eq "$dhcp_start" ]; then dhcp_start=$(( dhcp_start + 1 ))
    elif [ "$gw" -eq "$dhcp_end" ]; then dhcp_end=$(( dhcp_end - 1 )); fi
    [ "$dhcp_start" -le "$dhcp_end" ] || die "subnet too small for a DHCP pool; use a larger prefix"
}

# ---- state file (key=value) ----
state_set() {
    [ "$dry" = 1 ] && return 0
    local tmp="$STATE_FILE.tmp"
    { [ -f "$STATE_FILE" ] && grep -v "^$1=" "$STATE_FILE" || true; echo "$1=$2"; } > "$tmp"
    mv "$tmp" "$STATE_FILE"
}
load_state() {
    ipv4_forward="" ipv6_forward="" st_lan="" st_cidr="" st_added=0 st_dhcp=0 st_dns="" st_nat=1
    # shellcheck disable=SC1090
    [ ! -f "$STATE_FILE" ] || . "$STATE_FILE"
}

# ---- firewall ----
remove_rules() {
    local ipt="$1" spec
    # -D removes one match per call, so loop until every jump is gone.
    if [ "$dry" = 1 ]; then
        echo "+ $ipt -w -D FORWARD -j $FWD_CHAIN"
        echo "+ $ipt -w -D INPUT -j $IN_CHAIN"
        echo "+ $ipt -w -t nat -D POSTROUTING -j $NAT_CHAIN"
    else
        while "$ipt" -w -D FORWARD -j "$FWD_CHAIN" 2>/dev/null; do :; done
        while "$ipt" -w -D INPUT -j "$IN_CHAIN" 2>/dev/null; do :; done
        while "$ipt" -w -t nat -D POSTROUTING -j "$NAT_CHAIN" 2>/dev/null; do :; done
    fi
    for spec in "filter $FWD_CHAIN" "filter $IN_CHAIN" "nat $NAT_CHAIN"; do
        set -- $spec
        quiet "$ipt" -w -t "$1" -F "$2" || true
        quiet "$ipt" -w -t "$1" -X "$2" || true
    done
}

add_rules() {
    local ipt="$1" v="$2"
    run "$ipt" -w -N "$FWD_CHAIN"
    run "$ipt" -w -A "$FWD_CHAIN" -i "$lan" -o "$wan" -j ACCEPT
    run "$ipt" -w -A "$FWD_CHAIN" -i "$wan" -o "$lan" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    # Inserted first so it is evaluated before other tools' FORWARD policies (e.g. Docker's DROP).
    run "$ipt" -w -I FORWARD 1 -j "$FWD_CHAIN"
    if [ "$dhcp" = 1 ] && [ "$v" = 4 ]; then
        # Lets DHCP requests through a restrictive INPUT policy.
        run "$ipt" -w -N "$IN_CHAIN"
        run "$ipt" -w -A "$IN_CHAIN" -i "$lan" -p udp --sport 68 --dport 67 -j ACCEPT
        run "$ipt" -w -I INPUT 1 -j "$IN_CHAIN"
    fi
    if [ "$nat" = 1 ]; then
        run "$ipt" -w -t nat -N "$NAT_CHAIN"
        run "$ipt" -w -t nat -A "$NAT_CHAIN" -o "$wan" -j MASQUERADE
        run "$ipt" -w -t nat -I POSTROUTING 1 -j "$NAT_CHAIN"
    fi
    if [ "$v" = 6 ] && [ "$nat" = 1 ]; then
        echo "note: IPv6 masquerading needs kernel NAT66 support; delegate a prefix or use --no-nat if it fails" >&2
    fi
    return 0
}

# ---- DHCP (dnsmasq, DHCP only: --port=0 leaves DNS alone so it never clashes with a local resolver) ----
stop_dhcp() {
    [ "$dry" = 0 ] || return 0
    local pid
    if [ -f "$DHCP_PID" ]; then
        pid="$(cat "$DHCP_PID" 2>/dev/null || true)"
        if [ -n "$pid" ] && [ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" = dnsmasq ]; then
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 30); do [ -d "/proc/$pid" ] || break; sleep 0.1; done
        fi
        rm -f "$DHCP_PID"
    fi
    rm -f "$DHCP_LEASES"
}

start_dhcp() {
    run dnsmasq --conf-file=/dev/null --pid-file="$DHCP_PID" --dhcp-leasefile="$DHCP_LEASES" \
        --port=0 --interface="$lan" --bind-interfaces --dhcp-authoritative \
        --dhcp-range="$(int2ip "$dhcp_start"),$(int2ip "$dhcp_end"),$mask,12h" \
        --dhcp-option=3,"$gw_ip" --dhcp-option=6,"$dns"
}

# ---- reporting ----
print_network_info() {
    local gw example="" c
    gw="$(ip2int "$gw_ip")"
    for (( c = net_int + 1; c < bcast_int; c++ )); do
        [ "$c" -eq "$gw" ] && continue
        if [ "$dhcp" = 1 ] && [ "$c" -ge "$dhcp_start" ] && [ "$c" -le "$dhcp_end" ]; then continue; fi
        example="$(int2ip "$c")"; break
    done
    echo "LAN network $(int2ip "$net_int")/$prefix on $lan:"
    echo "  Gateway:  $gw_ip"
    echo "  Netmask:  $mask (/$prefix)"
    echo "  DNS:      ${dns//,/, }"
    if [ "$dhcp" = 1 ]; then
        echo "  DHCP:     $(int2ip "$dhcp_start") - $(int2ip "$dhcp_end"), served by dnsmasq on $lan"
    else
        echo "  DHCP:     off"
    fi
    if [ -n "$example" ]; then
        echo "  Static client example: address $example, netmask $mask, gateway $gw_ip, DNS ${dns//,/, }"
    fi
}

case "$cmd" in
    up)
        [ -n "$wan" ] && [ -n "$lan" ] || die "up needs --wan and --lan"
        [ "$wan" != "$lan" ] || die "--wan and --lan must be different interfaces"
        need_root; need_tool iptables; need_tool ip; need_tool sysctl
        [ "$v6" = 0 ] || need_tool ip6tables
        [ "$dhcp" = 0 ] || need_tool dnsmasq
        need_iface "$wan"; need_iface "$lan"
        [ -n "$dns" ] || dns="$DEFAULT_DNS"
        [[ "$dns" =~ ^[0-9A-Fa-f:.]+(,[0-9A-Fa-f:.]+)*$ ]] || die "invalid --dns list '$dns'"

        lan_cidr="$lan_cidr_arg"
        if [ -z "$lan_cidr" ]; then
            lan_cidr="$(ip -4 -o addr show dev "$lan" 2>/dev/null | awk '{print $4; exit}' || true)"
            [ -n "$lan_cidr" ] || die "$lan has no IPv4 address; pass --lan-address (e.g. 192.168.50.1/24)"
        fi
        parse_cidr "$lan_cidr"
        [ "$dhcp" = 0 ] || dhcp_pool

        load_state
        # Re-running up first removes our previous rules, DHCP server and address but keeps the original sysctls.
        for v in $(versions); do remove_rules "$(tables "$v")"; done
        stop_dhcp
        if [ "$dry" = 0 ] && [ ! -f "$STATE_FILE" ]; then
            state_set ipv4_forward "$(sysctl_get net.ipv4.ip_forward)"
            state_set ipv6_forward "$(sysctl_get net.ipv6.conf.all.forwarding)"
        fi

        added=0
        if [ "$st_added" = 1 ] && [ "$st_lan" = "$lan" ] && [ "$st_cidr" = "$lan_cidr" ]; then
            added=1
        elif [ "$st_added" = 1 ] && [ -n "$st_lan" ]; then
            quiet ip addr del "$st_cidr" dev "$st_lan" || true
        fi
        if [ -n "$lan_cidr_arg" ]; then
            present=""
            [ "$dry" = 1 ] || present="$(ip -4 -o addr show dev "$lan" | awk '{print $4}')"
            if ! grep -qx "$lan_cidr" <<<"$present"; then run ip addr add "$lan_cidr" dev "$lan"; added=1; fi
        fi
        run ip link set dev "$lan" up
        state_set st_lan "$lan"; state_set st_cidr "$lan_cidr"; state_set st_added "$added"
        state_set st_dhcp "$dhcp"; state_set st_dns "$dns"; state_set st_nat "$nat"

        run sysctl -qw net.ipv4.ip_forward=1
        [ "$v6" = 0 ] || run sysctl -qw net.ipv6.conf.all.forwarding=1
        for v in $(versions); do add_rules "$(tables "$v")" "$v"; done
        [ "$dhcp" = 0 ] || start_dhcp

        echo "gateway up: $lan -> $wan$([ "$nat" = 1 ] && echo ' (NAT)')"
        print_network_info
        ;;
    down)
        need_root; need_tool iptables
        [ "$v6" = 0 ] || need_tool ip6tables
        load_state
        for v in $(versions); do remove_rules "$(tables "$v")"; done
        stop_dhcp
        if [ "$dry" = 0 ] && [ -f "$STATE_FILE" ]; then
            [ "$st_added" != 1 ] || [ -z "$st_lan" ] || ip addr del "$st_cidr" dev "$st_lan" 2>/dev/null || true
            [ -z "$ipv4_forward" ] || sysctl -qw "net.ipv4.ip_forward=$ipv4_forward"
            [ -z "$ipv6_forward" ] || sysctl -qw "net.ipv6.conf.all.forwarding=$ipv6_forward" 2>/dev/null || true
            rm -f "$STATE_FILE"
        fi
        echo "gateway down"
        ;;
    status)
        need_root; need_tool iptables
        load_state
        echo "net.ipv4.ip_forward = $(sysctl_get net.ipv4.ip_forward)"
        if iptables -w -S "$FWD_CHAIN" 2>/dev/null; then
            iptables -w -t nat -S "$NAT_CHAIN" 2>/dev/null || true
            if [ -n "$st_cidr" ]; then
                lan="$st_lan" dhcp="$st_dhcp" dns="$st_dns"
                parse_cidr "$st_cidr"
                [ "$dhcp" = 0 ] || dhcp_pool
                print_network_info
            fi
        else
            echo "no $FWD_CHAIN chain (gateway not set up)"
        fi
        ;;
    -h|--help|help) usage 0 ;;
    *) usage 1 ;;
esac
