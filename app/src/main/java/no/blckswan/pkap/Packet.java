package no.blckswan.pkap;

public final class Packet {
    public final long timestampSeconds;
    public final int ipProtocol;
    public final String sourceAddress;
    public final String destinationAddress;
    public final int sourcePort;
    public final int destinationPort;
    public final byte[] payload;

    public Packet(long timestampSeconds, int ipProtocol, String sourceAddress,
                  String destinationAddress, int sourcePort, int destinationPort, byte[] payload) {
        this.timestampSeconds = timestampSeconds;
        this.ipProtocol = ipProtocol;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.payload = payload;
    }

    public String transportName() {
        if (ipProtocol == 6) return "TCP";
        if (ipProtocol == 17) return "UDP";
        return "IP/" + ipProtocol;
    }
}
