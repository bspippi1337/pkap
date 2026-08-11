package no.blckswan.pkap;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.InputStream;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final int OPEN_PCAP = 42;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private LinearLayout results;
    private TextView status;
    private ProgressBar progress;
    private Button openButton;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        int pad = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);
        root.setBackgroundColor(0xFF101214);

        TextView title = new TextView(this);
        title.setText("PKAP / native Android");
        title.setTextColor(0xFFF2F5F7);
        title.setTextSize(24);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Offline PCAP security analyzer. Suspicious authentication is flagged, secrets remain masked.");
        subtitle.setTextColor(0xFFB9C2C9);
        subtitle.setTextSize(14);
        subtitle.setPadding(0, dp(6), 0, dp(14));
        root.addView(subtitle);

        openButton = new Button(this);
        openButton.setText("OPEN .PCAP");
        openButton.setOnClickListener(v -> choosePcap());
        root.addView(openButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        progress = new ProgressBar(this);
        progress.setIndeterminate(true);
        progress.setVisibility(ProgressBar.GONE);
        LinearLayout.LayoutParams progressParams = new LinearLayout.LayoutParams(dp(32), dp(32));
        progressParams.gravity = Gravity.CENTER_HORIZONTAL;
        progressParams.topMargin = dp(10);
        root.addView(progress, progressParams);

        status = new TextView(this);
        status.setText("Choose a classic PCAP file to begin.");
        status.setTextColor(0xFFD6DDE2);
        status.setPadding(0, dp(10), 0, dp(10));
        root.addView(status);

        ScrollView scroll = new ScrollView(this);
        results = new LinearLayout(this);
        results.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(results);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
    }

    private void choosePcap() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                "application/vnd.tcpdump.pcap", "application/octet-stream", "*/*"
        });
        startActivityForResult(i, OPEN_PCAP);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != OPEN_PCAP || resultCode != RESULT_OK || data == null || data.getData() == null) return;
        analyze(data.getData());
    }

    private void analyze(Uri uri) {
        results.removeAllViews();
        progress.setVisibility(ProgressBar.VISIBLE);
        openButton.setEnabled(false);
        status.setText("Analyzing " + displayName(uri) + " …");

        worker.submit(() -> {
            try (InputStream in = getContentResolver().openInputStream(uri)) {
                if (in == null) throw new IllegalStateException("Could not open selected file");
                TrafficAnalyzer analyzer = new TrafficAnalyzer();
                PcapParser.Stats stats = PcapParser.parse(in, analyzer::inspect);
                List<Finding> findings = analyzer.getFindings();
                runOnUiThread(() -> showResults(stats, findings));
            } catch (Exception e) {
                runOnUiThread(() -> {
                    progress.setVisibility(ProgressBar.GONE);
                    openButton.setEnabled(true);
                    status.setText("Error: " + e.getMessage());
                });
            }
        });
    }

    private void showResults(PcapParser.Stats stats, List<Finding> findings) {
        progress.setVisibility(ProgressBar.GONE);
        openButton.setEnabled(true);
        status.setText(stats.packets + " packets read • " + stats.decodedTransportPackets +
                " TCP/UDP decoded • " + findings.size() + " findings • DLT " + stats.linkType);

        if (findings.isEmpty()) {
            addCard("INFO", "No matching insecure-authentication patterns were found.", "");
            return;
        }
        for (Finding f : findings) {
            String when = f.timestampSeconds > 0
                    ? DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM)
                    .format(new Date(f.timestampSeconds * 1000L)) : "";
            addCard(f.severity + " · " + f.protocol, f.summary,
                    f.source + "  →  " + f.destination + (when.isEmpty() ? "" : "\n" + when));
        }
    }

    private void addCard(String heading, String body, String meta) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        card.setBackgroundColor(0xFF1A1F23);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(8);

        TextView h = new TextView(this);
        h.setText(heading);
        h.setTextColor(0xFFF2F5F7);
        h.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        card.addView(h);

        TextView b = new TextView(this);
        b.setText(body);
        b.setTextColor(0xFFD6DDE2);
        b.setPadding(0, dp(4), 0, dp(3));
        card.addView(b);

        if (!meta.isEmpty()) {
            TextView m = new TextView(this);
            m.setText(meta);
            m.setTextColor(0xFF96A3AC);
            m.setTextSize(12);
            m.setTypeface(Typeface.MONOSPACE);
            card.addView(m);
        }
        results.addView(card, lp);
    }

    private String displayName(Uri uri) {
        try (android.database.Cursor c = getContentResolver().query(uri,
                new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) return c.getString(0);
        } catch (Exception ignored) {}
        return "capture.pcap";
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
