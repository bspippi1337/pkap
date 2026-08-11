package no.blckswan.pkap;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class TrafficAnalyzer {
    private static final int MAX_FINDINGS = 500;
    private final List<Finding> findings = new ArrayList<>();
    private final Set<String> seen = new HashSet<>();

    public void inspect(Packet p) {
        if (findings.size() >= MAX_FINDINGS || p.payload.length == 0) return;

        String text = new String(p.payload, StandardCharsets.ISO_8859_1);
        String lower = text.toLowerCase(Locale.ROOT);

        if (lower.contains("authorization: basic ")) {
            add(p, Finding.Severity.HIGH, "HTTP", "HTTP Basic authentication is visible in plaintext traffic");
        }
        if (containsPasswordField(lower)) {
            add(p, Finding.Severity.HIGH, "HTTP", "Possible cleartext login form contains a password field");
        }
        if (startsLine(text, "PASS ") && (p.sourcePort == 21 || p.destinationPort == 21)) {
            add(p, Finding.Severity.HIGH, "FTP", "FTP password command observed in plaintext");
        }
        if (startsLine(text, "USER ") && (p.sourcePort == 21 || p.destinationPort == 21)) {
            add(p, Finding.Severity.WARNING, "FTP", "FTP username command observed in plaintext");
        }
        if ((p.sourcePort == 110 || p.destinationPort == 110) &&
                (startsLine(text, "USER ") || startsLine(text, "PASS "))) {
            add(p, Finding.Severity.HIGH, "POP3", "POP3 login material is carried without transport encryption");
        }
        if ((p.sourcePort == 143 || p.destinationPort == 143) && lower.contains(" login ")) {
            add(p, Finding.Severity.HIGH, "IMAP", "IMAP LOGIN command observed without transport encryption");
        }
        if ((p.sourcePort == 25 || p.destinationPort == 25 || p.sourcePort == 587 || p.destinationPort == 587) &&
                (lower.contains("auth login") || lower.contains("auth plain"))) {
            add(p, Finding.Severity.HIGH, "SMTP", "SMTP AUTH observed before transport protection is evident");
        }
        if (containsBytes(p.payload, new byte[]{'N','T','L','M','S','S','P',0})) {
            add(p, Finding.Severity.WARNING, "NTLM", "NTLM authentication exchange observed; secret/hash material is intentionally not extracted");
        }
        if (p.sourcePort == 88 || p.destinationPort == 88) {
            add(p, Finding.Severity.INFO, "Kerberos", "Kerberos traffic observed; credential material is intentionally not extracted");
        }
        if (p.sourcePort == 161 || p.destinationPort == 161) {
            add(p, Finding.Severity.WARNING, "SNMP", "SNMP v1/v2 traffic may expose community strings; values are intentionally masked");
        }
        if (p.sourcePort == 23 || p.destinationPort == 23) {
            add(p, Finding.Severity.HIGH, "Telnet", "Telnet traffic is unencrypted and may expose interactive secrets");
        }
        if ((p.sourcePort == 80 || p.destinationPort == 80) && looksHttp(text)) {
            add(p, Finding.Severity.INFO, "HTTP", "Unencrypted HTTP application traffic observed");
        }
    }

    public List<Finding> getFindings() {
        return new ArrayList<>(findings);
    }

    private void add(Packet p, Finding.Severity severity, String protocol, String summary) {
        String src = p.sourceAddress + ":" + p.sourcePort;
        String dst = p.destinationAddress + ":" + p.destinationPort;
        String key = severity + "|" + protocol + "|" + src + "|" + dst + "|" + summary;
        if (!seen.add(key)) return;
        findings.add(new Finding(severity, protocol, src, dst, summary, p.timestampSeconds));
    }

    private static boolean containsPasswordField(String lower) {
        return lower.contains("password=") || lower.contains("passwd=") || lower.contains("pwd=") ||
                lower.contains("passwrd=") || lower.contains("j_password=") || lower.contains("session_password=");
    }

    private static boolean startsLine(String text, String token) {
        if (text.startsWith(token)) return true;
        return text.contains("\r\n" + token) || text.contains("\n" + token);
    }

    private static boolean looksHttp(String text) {
        return text.startsWith("GET ") || text.startsWith("POST ") || text.startsWith("PUT ") ||
                text.startsWith("DELETE ") || text.startsWith("HEAD ") || text.startsWith("HTTP/1.");
    }

    private static boolean containsBytes(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
