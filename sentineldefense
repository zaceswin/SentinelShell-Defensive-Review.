#!/usr/bin/env bash
# Defensive local security review menu. No traffic flooding, spoofing, evasion,
# credential collection, exploit execution, or unauthenticated file transfer.
set -Eeuo pipefail
IFS=$'\n\t'
readonly APP_NAME='SentinelShell Defensive Review'
readonly VERSION='1.0.0'

have() { command -v "$1" >/dev/null 2>&1; }

pause() {
	printf '\nPress Enter to continue...'
	IFS= read -r _ || true
}

section() {
	printf '\n== %s ==\n' "$1"
}

show_system() {
	section 'System information'
	printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
	printf 'Kernel: %s\n' "$(uname -sr 2>/dev/null || printf unknown)"
	if [[ -r /etc/os-release ]]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		printf 'OS: %s\n' "${PRETTY_NAME:-unknown}"
		fi
		printf 'Current user: %s\n' "$(id -un 2>/dev/null || printf unknown)"
		printf 'Elevated privileges: '
		if (( EUID == 0 )); then printf 'yes (root)\n'; else printf 'no\n'; fi
}

show_addresses() {
	section 'Local network addresses'
	if have ip; then
		ip -brief address 2>/dev/null || ip address 2>/dev/null || true
		elif have ifconfig; then
		ifconfig 2>/dev/null || true
		else
			printf 'Neither ip nor ifconfig is installed.\n'
			fi
			printf '\nDefault route:\n'
			if have ip; then ip route show default 2>/dev/null || true; fi
}

show_listeners() {
	section 'Listening services on this host'
	if have ss; then
		ss -lntup 2>/dev/null || ss -lntu 2>/dev/null || true
		elif have netstat; then
		netstat -lntup 2>/dev/null || netstat -lntu 2>/dev/null || true
		else
			printf 'Install iproute2 (ss) or net-tools (netstat) to list listeners.\n'
			fi
			printf '\nReview each listener and confirm it is expected and appropriately firewalled.\n'
}

check_firewall() {
	section 'Firewall status (read-only checks)'
	if have ufw; then
		printf '%s\n' '-- ufw --'
		ufw status verbose 2>&1 || true
		fi
		if have firewall-cmd; then
			printf '%s\n' '-- firewalld --'
			firewall-cmd --state 2>&1 || true
			firewall-cmd --list-all 2>&1 || true
			fi
			if have nft; then
				printf '%s\n' '-- nftables ruleset summary --'
				nft list ruleset 2>&1 | sed -n '1,100p' || true
				elif have iptables; then
				printf '%s\n' '-- iptables filter rules --'
				iptables -S 2>&1 || true
				fi
				if ! have ufw && ! have firewall-cmd && ! have nft && ! have iptables; then
					printf 'No supported firewall command found.\n'
					fi
					printf '\nThese commands report configuration; they do not change firewall settings.\n'
}

check_ssh() {
	section 'SSH server configuration (if present)'
	local cfg found=0
	for cfg in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
		[[ -f "$cfg" ]] || continue
		found=1
		printf '\n-- %s --\n' "$cfg"
		awk '
		/^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
		tolower($1) ~ /^(permitrootlogin|passwordauthentication|pubkeyauthentication|authenticationmethods|allowusers|allowgroups|port|x11forwarding|maxauthtries)$/ { print }
		' "$cfg" 2>/dev/null || true
		done
		if (( found == 0 )); then printf 'No standard sshd configuration file found.\n'; fi
			printf '\nEffective settings can differ due to included files and Match blocks; verify with the system sshd tools.\n'
}

check_updates() {
	section 'Update tooling availability'
	if have apt-get; then
		printf 'APT detected. To check package updates, run: sudo apt-get update && apt list --upgradable\n'
		elif have dnf; then
		printf 'DNF detected. To check package updates, run: sudo dnf check-update\n'
		elif have yum; then
		printf 'YUM detected. To check package updates, run: sudo yum check-update\n'
		elif have pacman; then
		printf 'Pacman detected. To check package updates, run: sudo pacman -Syup\n'
		elif have zypper; then
		printf 'Zypper detected. To check package updates, run: sudo zypper list-updates\n'
		else
			printf 'Package manager not recognized. Check your OS documentation for update commands.\n'
			fi
			printf 'This menu does not install updates or modify the system.\n'
}

check_file_hash() {
	section 'File hash (integrity aid)'
	local path
	read -r -p 'File path: ' path
	if [[ -z "$path" || ! -f "$path" || ! -r "$path" ]]; then
		printf 'Path is empty, unreadable, or not a regular file.\n'
		return
		fi
		if have sha256sum; then sha256sum -- "$path"
			elif have shasum; then shasum -a 256 -- "$path"
			else printf 'No SHA-256 utility found.\n'; fi
}

show_scope() {
	section 'Safe scope'
	cat <<'TEXT'
	This utility performs local, read-only checks. It does not scan arbitrary hosts,
	exploit weaknesses, bypass security controls, flood services, spoof traffic,
	or transfer files over unauthenticated connections.
	
	For an authorized assessment, define written scope and use approved tools with
	rate limits and monitoring. To assess a control weakness, document the affected
	asset, expected control, observed evidence, and remediation; do not attempt to
	circumvent protections on systems you do not own or administer.
	TEXT
}

main() {
	local choice
	clear 2>/dev/null || true
	cat <<'BANNER'
	_____            __  _            __ __         ____  __         __
	/ ___/__  ____  / /_(_)___  ___  / // /__  ___/ / /_/ /  ___  / /
	\__ \/ _ \/ __ \/ __/ / __ \/ _ \/ //_/ _ \/ _  / __/ _ \/ _ \/ /
	___/ /  __/ / / / /_/ / / / /  __/ ,< /  __/  __/ /_/  __/  __/ /
	/____/\___/_/ /_/\__/_/_/ /_/\___/_/|_|\___/\___/\__/\___/\___/_/
	
	Defensive local security review
	by zaceswin
	BANNER
	printf '\nWelcome to %s v%s.\n' "$APP_NAME" "$VERSION"
	printf '%s\n' 'Use only on systems you own or are authorized to administer.'
	while true; do
		printf '\n%s v%s\n' "$APP_NAME" "$VERSION"
		printf '%s\n' '1) System information' '2) Local addresses and default route' \
		'3) Listening services' '4) Firewall status' '5) SSH configuration review' \
		'6) Update check guidance' '7) Calculate a file SHA-256' '8) Safe-use scope' 'q) Quit'
		read -r -p 'Select: ' choice || break
		case "$choice" in
		1) show_system; pause ;;
	2) show_addresses; pause ;;
	3) show_listeners; pause ;;
	4) check_firewall; pause ;;
	5) check_ssh; pause ;;
	6) check_updates; pause ;;
	7) check_file_hash; pause ;;
	8) show_scope; pause ;;
	q|Q) break ;;
	*) printf 'Choose one of the listed options.\n' ;;
	esac
	done
	printf 'Goodbye.\n'
	circumvent protections on systems you do not own or administer.
	TEXT
}
}

main "$@"
