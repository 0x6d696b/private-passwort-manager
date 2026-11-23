#!/bin/sh
# Host-specific values are installed in a root-owned local configuration.
# Use iptables-nft on this host; never edit Docker's nftables tables directly.
set -eu
config_file=${PV_FIREWALL_CONFIG:-/etc/private-vault/firewall.conf}
if [ -f "$config_file" ]; then . "$config_file"; fi
: "${PV_LAN_IP:?Configure the private host IPv4 address}"
: "${PV_LAN_CIDR:?Configure the trusted private IPv4 subnet}"
: "${PV_LAN_INTERFACE:?Configure the LAN interface}"
iptables_bin=${PV_IPTABLES:-/usr/sbin/iptables}
chain=PV_PI_HTTPS

guard() {
    "$iptables_bin" -w 5 "$1" DOCKER-USER -p tcp -m conntrack \
        --ctdir ORIGINAL --ctorigdst "$PV_LAN_IP" --ctorigdstport 443 \
        -m comment --comment private-vault-update -j DROP
}
hook() {
    "$iptables_bin" -w 5 "$1" DOCKER-USER -p tcp -m conntrack \
        --ctdir ORIGINAL --ctorigdst "$PV_LAN_IP" --ctorigdstport 443 \
        -m comment --comment private-vault-https -j "$chain"
}

case "${1:-apply}" in
    apply)
        # Create the hook before Docker starts on boot; preserve all existing rules.
        "$iptables_bin" -w 5 -N DOCKER-USER 2>/dev/null || "$iptables_bin" -w 5 -L DOCKER-USER -n >/dev/null
        "$iptables_bin" -w 5 -N "$chain" 2>/dev/null || "$iptables_bin" -w 5 -L "$chain" -n >/dev/null
        guard -C >/dev/null 2>&1 || guard -I
        # Only our own chain is flushed. Leave the scoped guard if an update fails.
        "$iptables_bin" -w 5 -F "$chain"
        "$iptables_bin" -w 5 -A "$chain" -i "$PV_LAN_INTERFACE" -s "$PV_LAN_CIDR" -j RETURN
        "$iptables_bin" -w 5 -A "$chain" -j DROP
        while hook -C >/dev/null 2>&1; do hook -D; done
        hook -I
        "$iptables_bin" -w 5 -C FORWARD -j DOCKER-USER >/dev/null 2>&1 || \
            "$iptables_bin" -w 5 -I FORWARD 1 -j DOCKER-USER
        while guard -C >/dev/null 2>&1; do guard -D; done
        ;;
    remove)
        # Rebind the proxy to loopback BEFORE removing LAN restrictions.
        while hook -C >/dev/null 2>&1; do hook -D; done
        while guard -C >/dev/null 2>&1; do guard -D; done
        if "$iptables_bin" -w 5 -L "$chain" -n >/dev/null 2>&1; then
            "$iptables_bin" -w 5 -F "$chain"
            "$iptables_bin" -w 5 -X "$chain"
        fi
        ;;
    *) echo 'usage: private-vault-firewall [apply|remove]' >&2; exit 2 ;;
esac
