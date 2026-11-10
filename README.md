# SentinelShell-Defensive-Review.
A small Bash menu for reviewing basic security posture on the **local machine**. It reports system and network details, listening services, firewall configuration, selected SSH server settings, package manager update guidance, and SHA-256 file hashes.

This project is intended for defensive administration and learning. It performs local, read-only checks. It does not scan arbitrary hosts, exploit weaknesses, bypass security controls, flood services, spoof traffic, or transfer files.

## Features

- Shows operating system, kernel, current user, and privilege status
- Lists local interface addresses and the default route
- Displays listening TCP and UDP services, when `ss` or `netstat` is installed
- Reports status and rules from supported firewall tools (`ufw`, `firewalld`, `nftables`, or `iptables`)
- Shows selected SSH daemon configuration directives
- Identifies common package managers and prints update-check guidance
- Calculates a SHA-256 hash for a selected local file

## Requirements

- Bash 4 or newer is recommended
- Linux is the primary target
- Optional system utilities are detected at runtime; available checks depend on installed tools

No third-party packages are required by the script itself. Some status commands may need elevated privileges to show complete results. Run with `sudo` only when needed and only if you trust the script.

## Usage

Clone the repository, then run:

```bash
chmod +x pentmenu-safe.sh
./pentmenu-safe.sh
```

Or invoke it directly with Bash:

```bash
bash pentmenu-safe.sh
```

Choose a menu item by entering its number. Select `q` to quit.

## Interpreting results

The output is a quick local review, not a full security audit. A listed listening service is not automatically vulnerable; confirm that it is expected, appropriately configured, and restricted by host and network firewalls. SSH settings shown in files may not represent the effective configuration when includes or `Match` blocks apply. Verify important settings with your distribution's supported SSH tools and documentation.

The update option prints commands for your detected package manager but does not run them or install updates. Review package-manager output before applying changes.

## Authorized assessment

Use security testing tools only against assets you own or have explicit permission to assess. Define scope, timing, rate limits, and monitoring with the system owner. This project does not provide control-bypass or denial-of-service functionality.

## Contributing

Bug reports and defensive improvements are welcome. Keep changes focused on transparent, local, read-only checks. Please include the operating system and Bash version when reporting an issue, and avoid including secrets or sensitive host information.

## License

Released under the MIT License. See [LICENSE](LICENSE).
