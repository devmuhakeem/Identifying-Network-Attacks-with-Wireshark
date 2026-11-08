# Identifying Network Attacks with Wireshark

A hands-on network forensics lab analyzing four separate packet capture files with Wireshark, each demonstrating a different attack pattern: plaintext credential exposure over HTTP, a DNS-based remote shell, an FTP brute-force attempt, a SYN flooding DoS attack, and ARP poisoning.

## Scenario
A company suspected its network traffic contained evidence of various attacks. The task was to analyze a set of packet capture files with Wireshark, applying the right filters and protocol knowledge to identify and confirm each distinct attack pattern present.

## What I did

### 1. Plaintext credentials over HTTP (`HTTP Traffic.pcapng`)
- Filtered with `http` to isolate web traffic — confirmed it was unencrypted (plain HTTP, not HTTPS)
- Filtered further with `http.request.method == POST` (login/form submissions typically use POST, not GET)
- Expanded the **HTML Form URL Encoded** node in a filtered packet and found a user's login credentials submitted in plain, readable text

### 2. DNS-based remote shell (`DNS Remote Shell.pcap`)
- Filtered with `tcp.port == 53` to isolate traffic on DNS's standard port
- Traced a full TCP three-way handshake across specific packets (SYN → SYN-ACK → ACK) between an attacking IP and the target, confirming an established connection rather than a failed probe
- Used **Follow TCP Stream** to reconstruct the full conversation, revealing the attacker had performed a directory listing on the victim machine — confirming an active remote shell, not incidental traffic

### 3. FTP brute-force (`FTP Brute-Force.pcapng`)
- Filtered with `ftp.response.code == 530` (authentication failure) — found many repeated failed logins from one source IP against one target, the signature of automated credential guessing
- Filtered with `ftp.response.code == 230` (successful login) — confirmed the same source IP eventually succeeded, meaning the brute-force attempt worked

### 4. SYN flooding DoS (`SYN Flooding.pcapng`)
- Manually traced the broken handshake pattern: attacker sends SYN, victim responds SYN-ACK, attacker never completes with ACK — instead sends a new SYN or a RST, repeating the cycle and consuming victim resources
- Used **Statistics → I/O Graph** (filtered to TCP Errors) to visualize the attack as a spike in packets/second
- Used **Statistics → Protocol Hierarchy** to confirm an abnormally high proportion of TCP traffic relative to the rest of the capture — independent corroboration of the manual packet reading

### 5. ARP poisoning (`ARP Poisoning.pcapng`)
- Applied the `arp.duplicate-address-detected` filter — Wireshark's built-in detection directly surfaced a "Duplicate IP address detected" warning, confirming the spoofed/duplicated IP without needing manual packet-sequence tracing

## Key takeaways
- The right filter is the actual investigative skill — each filter (`http.request.method == POST`, `tcp.port == 53`, `ftp.response.code == 530/230`, `arp.duplicate-address-detected`) encodes specific knowledge of what that attack looks like at the protocol level
- Protocol-level understanding (POST vs. GET, the TCP handshake, FTP response codes) is what makes a deviation from normal behavior recognizable as an attack in the first place — the tool alone doesn't provide that
- Different attacks reveal themselves at different levels of effort: ARP poisoning was flagged automatically by Wireshark; a SYN flood needed manual tracing plus statistical corroboration; a DNS remote shell needed a full reconstructed conversation to find the actual evidence
- Plaintext protocols (HTTP, unencrypted FTP) are a demonstrable, not just theoretical, risk — watching real credentials appear in cleartext makes the case for encryption concrete
- Convergent evidence from multiple analysis methods (manual inspection + I/O graph + protocol statistics, for the SYN flood) builds a stronger, more confident finding than any single method alone

## Tools
Wireshark 3.2.6

---
*Completed in an isolated training lab environment using provided sample packet capture files.*
