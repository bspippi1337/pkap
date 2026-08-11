# PKAP native Android

A native Android port of the packet-analysis side of the original Pcredz-based repo.

## What changed

- No Python, Docker, Termux, libpcap or root required.
- Opens a classic `.pcap` with Android's Storage Access Framework.
- Streams the capture instead of loading the whole file into RAM.
- Supports Ethernet, Linux cooked v1 and Linux cooked v2 captures.
- Decodes IPv4/IPv6 plus TCP/UDP.
- Flags insecure authentication patterns such as HTTP Basic/forms, FTP, POP3, IMAP, SMTP AUTH, NTLM, Kerberos, SNMP and Telnet.
- Authentication secrets and reusable hashes are deliberately not extracted or written to disk.

## Build

Requires JDK 17, Android SDK 36 and Gradle 9.5.0.

```bash
gradle :app:assembleDebug
```

APK:

```text
app/build/outputs/apk/debug/app-debug.apk
```

The included GitHub Actions workflow builds the debug APK and uploads it as `pkap-debug-apk`.

## Current v0.1 limitations

- Classic PCAP only. PCAPNG is detected and rejected with a clear message.
- IPv6 extension headers are not walked yet.
- TCP stream reassembly is not implemented yet, so patterns split across packets may be missed.
- Offline import only; no live packet interception/VPN capture.
