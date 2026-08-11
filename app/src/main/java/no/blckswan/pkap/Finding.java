package no.blckswan.pkap;

public final class Finding {
    public enum Severity { INFO, WARNING, HIGH }

    public final Severity severity;
    public final String protocol;
    public final String source;
    public final String destination;
    public final String summary;
    public final long timestampSeconds;

    public Finding(Severity severity, String protocol, String source, String destination,
                   String summary, long timestampSeconds) {
        this.severity = severity;
        this.protocol = protocol;
        this.source = source;
        this.destination = destination;
        this.summary = summary;
        this.timestampSeconds = timestampSeconds;
    }
}
