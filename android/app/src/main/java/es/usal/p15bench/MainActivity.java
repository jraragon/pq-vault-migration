package es.usal.p15bench;

import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.Process;
import android.view.WindowManager;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/*
 * P15Bench.
 *  - Launched from the launcher (no extras): runs the selftest and the size table
 *    and shows them on screen.
 *  - Launched by the driver script with extras (suite, format, op, iters, warmup,
 *    nf, run_id): performs ONE run (the experimental unit) in this fresh process,
 *    writes <files>/p15/<run_id>.csv and then <run_id>.done, and finishes.
 */
public class MainActivity extends AppCompatActivity {

    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WindowCompat.enableEdgeToEdge(getWindow());
        setContentView(R.layout.activity_main);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        out = findViewById(R.id.output);

        Intent it = getIntent();
        if (it != null && it.hasExtra("suite")) startRun(it);
        else if (it != null && it.hasExtra("selftest_id")) startSelftestToFile(it.getStringExtra("selftest_id"));
        else startSelftest();
    }

    private void show(String s) { runOnUiThread(() -> out.setText(s)); }

    private void startSelftest() {
        show("Running selftest...");
        new Thread(() -> {
            String r;
            try { r = deviceInfo() + "\n" + P15Core.selftest() + "\n" + P15Core.sizes(); }
            catch (Exception e) { r = "ERROR: " + e; }
            show(r);
        }).start();
    }

    /** Driven by the run script before a timed session: writes <id>.txt, then <id>.done or <id>.error. */
    private void startSelftestToFile(String id) {
        show("Selftest before the session. Do not touch the phone.");
        new Thread(() -> {
            File dir = new File(getExternalFilesDir(null), "p15");
            dir.mkdirs();
            String r;
            try { r = deviceInfo() + "\n" + P15Core.selftest(); } catch (Exception e) { r = "ERROR: " + e; }
            try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(dir, id + ".txt")), StandardCharsets.UTF_8))) {
                w.print(r);
            } catch (Exception ignored) { }
            try { new FileOutputStream(new File(dir, id + (r.contains("SELFTEST PASSED") ? ".done" : ".error"))).close(); }
            catch (Exception ignored) { }
            show(r);
            runOnUiThread(this::finishAndRemoveTask);
        }).start();
    }

    private void startRun(Intent it) {
        final String suite = it.getStringExtra("suite"), fmt = it.getStringExtra("format"),
                op = it.getStringExtra("op"), runId = it.getStringExtra("run_id");
        final int iters = it.getIntExtra("iters", 1000), warmup = it.getIntExtra("warmup", 50),
                nf = it.getIntExtra("nf", 7);
        show("Run " + runId + " in progress. Do not touch the phone.");
        Thread t = new Thread(() -> {
            File dir = new File(getExternalFilesDir(null), "p15");
            dir.mkdirs();
            File csv = new File(dir, runId + ".csv"), done = new File(dir, runId + ".done");
            try {
                Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_DISPLAY);
                String before = thermal();
                long[] ns = P15Core.bench(P15Core.Suite.of(suite), P15Core.Fmt.of(fmt), op, iters, warmup, nf);
                String after = thermal();
                try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(csv), StandardCharsets.UTF_8))) {
                    w.println("# p15_android bench");
                    w.println("# " + deviceInfo().replace("\n", "\n# "));
                    w.println("# suite=" + suite + " format=" + fmt + " op=" + op + " iters=" + iters + " warmup=" + warmup + " nf=" + nf);
                    w.println("# run_id=" + runId);
                    w.println("# thermal_before=" + before);
                    w.println("# thermal_after=" + after);
                    w.println("# time_source=System.nanoTime");
                    w.println("run_id,suite,format,op,iter,ns");
                    for (int i = 0; i < ns.length; i++)
                        w.println(runId + "," + suite + "," + fmt + "," + op + "," + i + "," + ns[i]);
                }
                new FileOutputStream(done).close();
                show("Run " + runId + " finished.");
            } catch (Exception e) {
                try (PrintWriter w = new PrintWriter(new FileOutputStream(new File(dir, runId + ".error")))) { e.printStackTrace(w); }
                catch (Exception ignored) { }
                show("ERROR in " + runId + ": " + e);
            }
            runOnUiThread(this::finishAndRemoveTask);
        });
        t.start();
    }

    private String thermal() {
        Intent b = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        float temp = b == null ? -1 : b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -10) / 10f;
        int level = b == null ? -1 : b.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int plugged = b == null ? -1 : b.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        int status = pm.getCurrentThermalStatus();
        float headroom = Build.VERSION.SDK_INT >= 30 ? pm.getThermalHeadroom(0) : Float.NaN;
        return "battery_temp_c=" + temp + " battery_level=" + level + " plugged=" + plugged +
               " thermal_status=" + status + " thermal_headroom=" + headroom;
    }

    private String deviceInfo() {
        String soc = Build.VERSION.SDK_INT >= 31 ? Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL : "n/a";
        return "device=" + Build.MANUFACTURER + " " + Build.MODEL + " (" + Build.DEVICE + ")\n" +
               "soc=" + soc + "\n" +
               "android=" + Build.VERSION.RELEASE + " sdk=" + Build.VERSION.SDK_INT + " build=" + Build.DISPLAY + "\n" +
               "security_patch=" + Build.VERSION.SECURITY_PATCH + "\n" +
               "bouncycastle=" + P15Core.bcVersion() + "\n" +
               "app_debuggable=" + ((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0);
    }
}
