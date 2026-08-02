# Network Security Auditing Tool

A lightweight Bash script for auditing network security on macOS. Designed for use with a VPN and DNS-over-HTTPS setup, it passively captures and analyzes live traffic to check for common privacy leaks.

## Why I Created the Tool

As I learn some networking basics, I have begun to learn the ease with which personal data is captured through network analysis and/or website scraping. Understanding this at a surface level let me do research into aggressive HTTPS, DNS resolvers, DoH and VPN usage, and general private network protections. Beginning to dive into those services/tools then allowed me to dive into Wireshark to see how they actually work on the live network, thus leading me to use `tcpdump` in the Bash terminal on macOS. Once I brewed `tcpdump`, I then got familiar with the commands and services provided. That then gave me the idea to craft a program that would test the authenticity of my DNS, DoH, and VPN services with one click, rather than checking whether everything was active in its respective way. All of this has culminated in my first cyber/networking tool. This is a simple Bash script that I have saved under an alias to run on my home Wi-Fi (switching between Ethernet and wireless toggling), or more realistically, when I connect to public Wi-Fi on my laptop. In its current state, it is highly customizable, and I will likely improve upon it as I learn more.

This being said, let me mention a few use cases, how it works, how to use it, dependencies, and what I learned while making it!

## Use Cases
 
- Verifying VPN is tunneling all traffic before and after connecting
- Confirming DNS-over-HTTPS is active and not silently falling back to plaintext
- Spot-checking after a system update, VPN config change, or network switch
- Identifying which process is generating traffic on a suspicious port
- Understanding what the inside vs. outside of a WireGuard tunnel looks like at the packet level

## How It Works
 
The script uses `tcpdump` to capture packets on your physical interface (`en0`) and/or WireGuard tunnel interface (`utun*`), then evaluates the results against six security checks. Interface detection is automatic; thus, it reads your active route and inspects `ifconfig` for the WireGuard tunnel rather than hardcoding values.
 
Each test produces a `[ PASS ]`, `[ FAIL ]`, `[ WARN ]`, or `[ INFO ]` verdict. Running all tests sequentially generates a final summary with an overall status.
 
## Tests
 
| # | Name | Interface | What It Checks |
|---|------|-----------|----------------|
| 1 | DNS Leak Check | Physical | Listens for UDP port 53 traffic. Any hits mean DNS queries are leaving unencrypted. |
| 2 | DoH Verification | Physical | Confirms DNS is routing to Cloudflare `1.1.1.1` over HTTPS (port 443). A WARN here is expected if DoH routes inside the tunnel. |
| 3 | VPN Integrity | Physical | Captures everything except WireGuard UDP traffic. Near-silence is the goal — any IP traffic is a potential tunnel bypass. |
| 4 | Encrypted View | Physical | Shows raw WireGuard envelopes on the physical interface. Confirms the tunnel is active and carrying traffic. |
| 5 | Decrypted View | Tunnel | Captures plaintext-visible traffic inside the tunnel. Real IPs and protocols are visible here; application-layer TLS is still encrypted. |
| 6 | Process Hunt | Tunnel | Takes a port number, runs `lsof` and `netstat` to identify the owning process, then captures live tunnel traffic on that port. |
| 7 | Run All | Both | Runs tests 1–5 sequentially (configurable duration, default 10s each) and prints a full summary. |
| 8 | Install Aliases | — | Writes `dns-leak`, `doh-check`, `vpn-integrity`, `wg-view`, `tunnel-view`, and `port-hunt` shortcuts to `~/.zshrc`. |
 
## Usage
 
```bash
chmod +x network_audit.sh
sudo ./network_audit.sh
```
 
You'll get an interactive menu. Select a test by number or run all with `7`. After installing aliases with `8`, run `source ~/.zshrc` once and then call any test directly:
 
```bash
dns-leak        # live UDP 53 monitor
vpn-integrity   # live bypass check
tunnel-view     # decrypted traffic inside tunnel
port-hunt       # lsof -i shortcut
```
 
Configuration variables at the top of the script:
 
```bash
PHYSICAL_INTERFACE="en0"   # override if auto-detect fails
WIREGUARD_PORT="51820"     # change for non-NordLynx WireGuard setups
DOH_SERVER="1.1.1.1"       # swap for your DoH provider
SEQUENTIAL_DURATION=10     # seconds per test in Run All
```
## My Dependencies
 
- macOS (Apple Silicon; what I use)
- `tcpdump`: built-in, though it does require `sudo`
- `lsof`, `netstat`, `ifconfig`, `route`, `awk`: standard macOS CLI tools
- WireGuard VPN (NordVPN NordLynx or OS equivalent)

## What I Learned Building This

This was my first Bash project not on Linux, so I wanted to note the primary things that I learned:

- **macOS `tcpdump` BPF filter quoting** is strict in ways that differ from Linux, meaning certain filter expressions that work on Linux fail silently or throw errors on macOS. Getting the capture filters right required testing each one in isolation.

- **`mktemp` behaves differently on macOS.** It doesn't accept a full path like `/tmp/file_XXXXXX.txt` the way Linux does. The correct macOS syntax uses the `-t` flag with just a prefix, and the OS handles temp directory placement itself. This broke the script silently until I traced it to temp file creation.

- **`sudo` doesn't affect redirects in Bash.** A line like `sudo tcpdump ... >> file` elevates `tcpdump` but not the redirect; the file write still runs as the current user. The fix is piping through `sudo tee -a` instead.

- **Auto-detecting the active interface** with `route get default | awk` is more reliable than hardcoding `en0`, especially on machines that switch between WiFi and Ethernet or use VPN virtual interfaces.

- **ShellCheck** (`brew install shellcheck`) is worth running on any Bash script before calling it done. It caught the redirect issue above, flagged `read` calls missing `-r` that would mangle backslashes, and surfaced two unused variable warnings that revealed dead code paths in the original draft.
