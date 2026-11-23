#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run this installer as root (sudo).' >&2; exit 1; }
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
configuration=/etc/private-vault/firewall.conf
if [ "$#" -eq 3 ]; then
    umask 077
    temporary=$(mktemp)
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    python3 - "$@" > "$temporary" <<'PYCONFIG'
import ipaddress, re, sys
address = ipaddress.IPv4Address(sys.argv[1])
network = ipaddress.IPv4Network(sys.argv[2], strict=True)
interface = sys.argv[3]
if not address.is_private or address.is_loopback or not network.is_private or network.prefixlen < 8 or address not in network:
    raise SystemExit('Provide a private host IPv4 address within the trusted private subnet')
if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
    raise SystemExit('Invalid LAN interface')
print('PV_LAN_IP=' + str(address))
print('PV_LAN_CIDR=' + str(network))
print('PV_LAN_INTERFACE=' + interface)
PYCONFIG
    install -d -o root -g root -m 0700 /etc/private-vault
    install -o root -g root -m 0600 "$temporary" "$configuration"
elif [ "$#" -ne 0 ] || [ ! -f "$configuration" ]; then
    echo 'usage: sudo sh deploy/install-pi-firewall.sh PRIVATE_IP TRUSTED_CIDR LAN_INTERFACE' >&2
    echo 'With no arguments, an existing installed configuration is required.' >&2
    exit 2
fi

install -o root -g root -m 0755 "$directory/pi-firewall.sh" /usr/local/sbin/private-vault-firewall
install -o root -g root -m 0644 "$directory/private-vault-firewall.service" /etc/systemd/system/private-vault-firewall.service
install -d -o root -g root -m 0755 /etc/systemd/system/docker.service.d
install -o root -g root -m 0644 "$directory/docker-firewall.conf" /etc/systemd/system/docker.service.d/private-vault-firewall.conf
systemctl daemon-reload
systemctl enable private-vault-firewall.service
if systemctl is-active --quiet private-vault-firewall.service; then
    systemctl reload private-vault-firewall.service
else
    systemctl start private-vault-firewall.service
fi
printf '%s\n' 'HTTPS firewall installed. Docker and existing containers were not restarted.'
