package no.blckswan.pkap;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Arrays;

public final class PcapParser {
    public interface PacketConsumer {
        void accept(Packet packet);
    }

    public static final class Stats {
        public long packets;
        public long decodedTransportPackets;
        public int linkType;
    }

    private static final int DLT_EN10MB = 1;
    private static final int DLT_LINUX_SLL = 113;
    private static final int DLT_LINUX_SLL2 = 276;
    private static final int MAX_PACKET = 4 * 1024 * 1024;

    private PcapParser() {}

    public static Stats parse(InputStream raw, PacketConsumer consumer) throws IOException {
        BufferedInputStream in = new BufferedInputStream(raw, 128 * 1024);
        byte[] global = readExact(in, 24);
        Endian endian = parseMagic(global);
        int linkType = (int) u32(global, 20, endian);
        if (linkType != DLT_EN10MB && linkType != DLT_LINUX_SLL && linkType != DLT_LINUX_SLL2) {
            throw new IOException("Unsupported PCAP link type: " + linkType +
                    " (supported: Ethernet, Linux cooked v1/v2)");
        }

        Stats stats = new Stats();
        stats.linkType = linkType;

        while (true) {
            byte[] header;
            try {
                header = readExact(in, 16);
            } catch (EOFException eof) {
                break;
            }

            long tsSec = u32(header, 0, endian);
            long inclLenLong = u32(header, 8, endian);
            if (inclLenLong < 0 || inclLenLong > MAX_PACKET) {
                throw new IOException("Refusing suspicious packet length: " + inclLenLong);
            }
            int inclLen = (int) inclLenLong;
            byte[] frame = readExact(in, inclLen);
            stats.packets++;

            Packet packet = decodeFrame(frame, linkType, tsSec);
            if (packet != null) {
                stats.decodedTransportPackets++;
                consumer.accept(packet);
            }
        }
        return stats;
    }

    private static Packet decodeFrame(byte[] frame, int linkType, long tsSec) {
        try {
            int offset;
            int etherType;
            if (linkType == DLT_EN10MB) {
                if (frame.length < 14) return null;
                etherType = u16be(frame, 12);
                offset = 14;
                if (etherType == 0x8100 || etherType == 0x88A8) {
                    if (frame.length < 18) return null;
                    etherType = u16be(frame, 16);
                    offset = 18;
                }
            } else if (linkType == DLT_LINUX_SLL) {
                if (frame.length < 16) return null;
                etherType = u16be(frame, 14);
                offset = 16;
            } else {
                if (frame.length < 20) return null;
                etherType = u16be(frame, 0);
                offset = 20;
            }

            if (etherType == 0x0800) return decodeIpv4(frame, offset, tsSec);
            if (etherType == 0x86DD) return decodeIpv6(frame, offset, tsSec);
            return null;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static Packet decodeIpv4(byte[] b, int off, long tsSec) {
        if (b.length < off + 20) return null;
        int version = (b[off] >>> 4) & 0x0F;
        int ihl = (b[off] & 0x0F) * 4;
        if (version != 4 || ihl < 20 || b.length < off + ihl) return null;
        int proto = b[off + 9] & 0xFF;
        String src = ipv4(b, off + 12);
        String dst = ipv4(b, off + 16);
        return decodeTransport(b, off + ihl, proto, src, dst, tsSec);
    }

    private static Packet decodeIpv6(byte[] b, int off, long tsSec) {
        if (b.length < off + 40) return null;
        int version = (b[off] >>> 4) & 0x0F;
        if (version != 6) return null;
        int next = b[off + 6] & 0xFF;
        String src = ipv6(b, off + 8);
        String dst = ipv6(b, off + 24);
        if (next != 6 && next != 17) return null;
        return decodeTransport(b, off + 40, next, src, dst, tsSec);
    }

    private static Packet decodeTransport(byte[] b, int off, int proto, String src, String dst, long tsSec) {
        if (proto == 6) {
            if (b.length < off + 20) return null;
            int srcPort = u16be(b, off);
            int dstPort = u16be(b, off + 2);
            int tcpHeader = ((b[off + 12] >>> 4) & 0x0F) * 4;
            if (tcpHeader < 20 || b.length < off + tcpHeader) return null;
            return new Packet(tsSec, proto, src, dst, srcPort, dstPort,
                    Arrays.copyOfRange(b, off + tcpHeader, b.length));
        }
        if (proto == 17) {
            if (b.length < off + 8) return null;
            int srcPort = u16be(b, off);
            int dstPort = u16be(b, off + 2);
            return new Packet(tsSec, proto, src, dst, srcPort, dstPort,
                    Arrays.copyOfRange(b, off + 8, b.length));
        }
        return null;
    }

    private static Endian parseMagic(byte[] h) throws IOException {
        int b0 = h[0] & 0xFF, b1 = h[1] & 0xFF, b2 = h[2] & 0xFF, b3 = h[3] & 0xFF;
        if (b0 == 0xD4 && b1 == 0xC3 && b2 == 0xB2 && b3 == 0xA1) return Endian.LITTLE;
        if (b0 == 0x4D && b1 == 0x3C && b2 == 0xB2 && b3 == 0xA1) return Endian.LITTLE;
        if (b0 == 0xA1 && b1 == 0xB2 && b2 == 0xC3 && b3 == 0xD4) return Endian.BIG;
        if (b0 == 0xA1 && b1 == 0xB2 && b2 == 0x3C && b3 == 0x4D) return Endian.BIG;
        if (b0 == 0x0A && b1 == 0x0D && b2 == 0x0D && b3 == 0x0A) {
            throw new IOException("PCAPNG detected. Convert to classic .pcap for v0.1.");
        }
        throw new IOException("Not a classic PCAP file");
    }

    private enum Endian { LITTLE, BIG }

    private static long u32(byte[] b, int o, Endian e) {
        if (e == Endian.LITTLE) {
            return ((long)b[o] & 0xFF) |
                    (((long)b[o+1] & 0xFF) << 8) |
                    (((long)b[o+2] & 0xFF) << 16) |
                    (((long)b[o+3] & 0xFF) << 24);
        }
        return (((long)b[o] & 0xFF) << 24) |
                (((long)b[o+1] & 0xFF) << 16) |
                (((long)b[o+2] & 0xFF) << 8) |
                ((long)b[o+3] & 0xFF);
    }

    private static int u16be(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF);
    }

    private static String ipv4(byte[] b, int o) {
        return (b[o] & 0xFF) + "." + (b[o+1] & 0xFF) + "." +
                (b[o+2] & 0xFF) + "." + (b[o+3] & 0xFF);
    }

    private static String ipv6(byte[] b, int o) {
        try {
            return InetAddress.getByAddress(Arrays.copyOfRange(b, o, o + 16)).getHostAddress();
        } catch (Exception e) {
            return "?";
        }
    }

    private static byte[] readExact(InputStream in, int len) throws IOException {
        byte[] b = new byte[len];
        int pos = 0;
        while (pos < len) {
            int n = in.read(b, pos, len - pos);
            if (n < 0) throw new EOFException();
            pos += n;
        }
        return b;
    }
}
