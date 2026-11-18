package com.guard;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputFilter;
import android.util.Base64;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

public class MainActivity extends Activity {
    private static final String SERVER_URL = "http://47.95.119.39:8899/verify";
    private static final String SECRET_KEY = "NG_PRO_99887766_KEY";
    private static final int REQ_VPN = 1001;
    private static final int REQ_OVERLAY = 1002;

    private TextView tvStatus, tvExpire;
    private EditText etKey;
    private Button btnPower, btnVerify, btnStrict, btnFloat;
    private SharedPreferences sp;
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= 21) {
            getWindow().setStatusBarColor(Color.parseColor("#090D16"));
            getWindow().setNavigationBarColor(Color.parseColor("#090D16"));
        }
        sp = getSharedPreferences("guard_prefs", MODE_PRIVATE);
        GuardVpnService.strictMode = sp.getBoolean("strict_mode", false);
        buildCyberUI();

        String savedKey = sp.getString("license_key", "");
        if (savedKey.length() == 10) {
            etKey.setText(savedKey);
            verifyKey(savedKey, true);
        }
    }

    private void buildCyberUI() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.parseColor("#090D16"));
        scroll.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(36), dp(20), dp(30));
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView title = new TextView(this);
        title.setText("极速助手 PRO");
        title.setTextColor(Color.parseColor("#00E5FF"));
        title.setTextSize(26);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setLetterSpacing(0.12f);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("安全稳定 · 一键切换");
        sub.setTextColor(Color.parseColor("#64748B"));
        sub.setTextSize(12);
        sub.setPadding(0, dp(4), 0, dp(24));
        root.addView(sub);

        btnPower = new Button(this);
        btnPower.setText("未激活");
        btnPower.setTextColor(Color.WHITE);
        btnPower.setTextSize(18);
        btnPower.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams powerLp = new LinearLayout.LayoutParams(dp(145), dp(145));
        powerLp.bottomMargin = dp(14);
        btnPower.setLayoutParams(powerLp);
        btnPower.setOnClickListener(v -> toggleVpn());
        root.addView(btnPower);

        tvStatus = new TextView(this);
        tvStatus.setText("当前状态：未激活");
        tvStatus.setTextColor(Color.parseColor("#94A3B8"));
        tvStatus.setTextSize(14);
        tvStatus.setPadding(0, 0, 0, dp(20));
        root.addView(tvStatus);

        LinearLayout cardAuth = createCard();
        TextView lbKey = new TextView(this);
        lbKey.setText("授权卡密");
        lbKey.setTextColor(Color.parseColor("#E2E8F0"));
        lbKey.setTextSize(14);
        lbKey.setTypeface(Typeface.DEFAULT_BOLD);
        cardAuth.addView(lbKey);

        etKey = new EditText(this);
        etKey.setHint("请输入 10 位卡密");
        etKey.setHintTextColor(Color.parseColor("#475569"));
        etKey.setTextColor(Color.parseColor("#00E5FF"));
        etKey.setTextSize(16);
        etKey.setSingleLine(true);
        etKey.setFilters(new InputFilter[]{new InputFilter.LengthFilter(10), new InputFilter.AllCaps()});
        etKey.setBackground(roundBg("#0F172A", "#1E293B", dp(10)));
        etKey.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams etLp = new LinearLayout.LayoutParams(-1, -2);
        etLp.topMargin = dp(10);
        etLp.bottomMargin = dp(12);
        etKey.setLayoutParams(etLp);
        cardAuth.addView(etKey);

        btnVerify = new Button(this);
        btnVerify.setText("立即激活");
        btnVerify.setTextColor(Color.WHITE);
        btnVerify.setTextSize(14);
        btnVerify.setTypeface(Typeface.DEFAULT_BOLD);
        btnVerify.setBackground(roundBg("#2563EB", "#3B82F6", dp(10)));
        btnVerify.setOnClickListener(v -> verifyKey(etKey.getText().toString().trim().toUpperCase(), false));
        cardAuth.addView(btnVerify);

        tvExpire = new TextView(this);
        tvExpire.setText("到期时间：未激活");
        tvExpire.setTextColor(Color.parseColor("#64748B"));
        tvExpire.setTextSize(12);
        tvExpire.setPadding(0, dp(10), 0, 0);
        cardAuth.addView(tvExpire);
        root.addView(cardAuth);

        LinearLayout cardTools = createCard();
        btnStrict = new Button(this);
        btnStrict.setTextColor(Color.WHITE);
        btnStrict.setTextSize(14);
        btnStrict.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams sLp = new LinearLayout.LayoutParams(-1, -2);
        sLp.bottomMargin = dp(12);
        btnStrict.setLayoutParams(sLp);
        btnStrict.setOnClickListener(v -> toggleStrictMode());
        cardTools.addView(btnStrict);

        btnFloat = new Button(this);
        btnFloat.setText("开启悬浮开关");
        btnFloat.setTextColor(Color.WHITE);
        btnFloat.setTextSize(14);
        btnFloat.setTypeface(Typeface.DEFAULT_BOLD);
        btnFloat.setBackground(roundBg("#0F766E", "#14B8A6", dp(10)));
        btnFloat.setOnClickListener(v -> toggleFloatingWindow());
        cardTools.addView(btnFloat);

        TextView tip = new TextView(this);
        tip.setText("提示：长按悬浮球 1 秒可隐藏至通知栏，点击通知栏随时呼出");
        tip.setTextColor(Color.parseColor("#64748B"));
        tip.setTextSize(11);
        tip.setPadding(0, dp(10), 0, 0);
        cardTools.addView(tip);
        root.addView(cardTools);

        scroll.addView(root);
        setContentView(scroll);
        refreshUI();
    }

    private void toggleStrictMode() {
        GuardVpnService.strictMode = !GuardVpnService.strictMode;
        sp.edit().putBoolean("strict_mode", GuardVpnService.strictMode).apply();
        refreshUI();
        Toast.makeText(this, GuardVpnService.strictMode ? "强力模式已开启" : "强力模式已关闭", Toast.LENGTH_SHORT).show();
        if (GuardVpnService.isRunning) {
            Intent restart = new Intent(this, GuardVpnService.class);
            restart.setAction("RESTART");
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(restart);
            else startService(restart);
        }
    }

    private LinearLayout createCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackground(roundBg("#131B2E", "#1E293B", dp(16)));
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(16);
        card.setLayoutParams(lp);
        return card;
    }

    private GradientDrawable roundBg(String fill, String stroke, int radius) {
        GradientDrawable gd = new GradientDrawable();
        gd.setColor(Color.parseColor(fill));
        gd.setCornerRadius(radius);
        gd.setStroke(dp(1), Color.parseColor(stroke));
        return gd;
    }

    private void refreshUI() {
        GradientDrawable circle = new GradientDrawable();
        circle.setShape(GradientDrawable.OVAL);
        if (!GuardVpnService.isAuthorized) {
            circle.setColor(Color.parseColor("#1E293B"));
            circle.setStroke(dp(3), Color.parseColor("#F59E0B"));
            btnPower.setText("未激活");
            tvStatus.setText("当前状态：未激活");
        } else if (GuardVpnService.isRunning) {
            circle.setColor(Color.parseColor("#064E3B"));
            circle.setStroke(dp(4), Color.parseColor("#10B981"));
            btnPower.setText("已开启");
            tvStatus.setText("当前状态：运行中");
        } else {
            circle.setColor(Color.parseColor("#172554"));
            circle.setStroke(dp(4), Color.parseColor("#3B82F6"));
            btnPower.setText("点击开启");
            tvStatus.setText("当前状态：已就绪");
        }
        btnPower.setBackground(circle);

        if (GuardVpnService.strictMode) {
            btnStrict.setText("强力模式：已开启");
            btnStrict.setBackground(roundBg("#7C2D12", "#F97316", dp(10)));
        } else {
            btnStrict.setText("强力模式：已关闭");
            btnStrict.setBackground(roundBg("#1E293B", "#334155", dp(10)));
        }
    }

    private String decryptData(String b64) throws Exception {
        byte[] raw = Base64.decode(b64, Base64.DEFAULT);
        byte[] salt = new byte[8];
        System.arraycopy(raw, 0, salt, 0, 8);
        int dataLen = raw.length - 8;
        byte[] out = new byte[dataLen];
        byte[] secret = SECRET_KEY.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        int pos = 0, blockIdx = 0;
        while (pos < dataLen) {
            md.reset();
            md.update(secret);
            md.update(salt);
            md.update(new byte[]{(byte)(blockIdx >> 24), (byte)(blockIdx >> 16), (byte)(blockIdx >> 8), (byte)blockIdx});
            byte[] ks = md.digest();
            for (int i = 0; i < ks.length && pos < dataLen; i++) {
                out[pos] = (byte)(raw[8 + pos] ^ ks[i]);
                pos++;
            }
            blockIdx++;
        }
        return new String(out, "UTF-8");
    }

    private Set<String> parseSet(JSONObject json, String key, boolean lower) {
        Set<String> set = new HashSet<>();
        JSONArray arr = json.optJSONArray(key);
        if (arr != null) {
            for (int i = 0; i < arr.length(); i++) {
                String s = arr.optString(i, "").trim();
                if (!s.isEmpty()) set.add(lower ? s.toLowerCase() : s);
            }
        }
        return set;
    }

    private void verifyKey(String key, boolean silent) {
        if (key.length() != 10) {
            if (!silent) Toast.makeText(this, "请输入 10 位数卡密", Toast.LENGTH_SHORT).show();
            return;
        }
        btnVerify.setText("验证中...");
        new Thread(() -> {
            try {
                String udid = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
                URL url = new URL(SERVER_URL + "?key=" + key + "&udid=" + udid + "&enc=1");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(6000);
                conn.setReadTimeout(6000);
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
                br.close();

                JSONObject resp = new JSONObject(sb.toString());
                int code = resp.optInt("code", 500);

                if (code == 200 && resp.has("data")) {
                    JSONObject json = new JSONObject(decryptData(resp.getString("data")));
                    String msg = json.optString("msg", "已激活");
                    String token = json.optString("token", "");

                    GuardVpnService.blockedDomains = parseSet(json, "domains", true);
                    GuardVpnService.blockedIPs = parseSet(json, "ips", false);
                    GuardVpnService.whitelistDomains = parseSet(json, "w_domains", true);
                    GuardVpnService.whitelistIPs = parseSet(json, "w_ips", false);
                    GuardVpnService.targetApps = parseSet(json, "apps", false);
                    GuardVpnService.currentKey = key;
                    GuardVpnService.sessionToken = token;
                    GuardVpnService.isAuthorized = true;
                    sp.edit().putString("license_key", key).apply();

                    handler.post(() -> {
                        btnVerify.setText("刷新状态");
                        tvExpire.setText(msg);
                        refreshUI();
                        if (!silent) Toast.makeText(this, "激活成功", Toast.LENGTH_SHORT).show();
                    });
                } else {
                    String msg = resp.optString("msg", "验证失败");
                    GuardVpnService.isAuthorized = false;
                    handler.post(() -> {
                        btnVerify.setText("立即激活");
                        tvExpire.setText("验证失败：" + msg);
                        refreshUI();
                        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
                    });
                }
            } catch (Exception e) {
                handler.post(() -> {
                    btnVerify.setText("立即激活");
                    if (!silent) Toast.makeText(this, "连接失败，请重试", Toast.LENGTH_SHORT).show();
                });
            }
        }).start();
    }

    private void toggleVpn() {
        if (!GuardVpnService.isAuthorized) {
            Toast.makeText(this, "请先输入卡密激活", Toast.LENGTH_SHORT).show();
            return;
        }
        if (GuardVpnService.isRunning) {
            Intent stop = new Intent(this, GuardVpnService.class);
            stop.setAction("STOP");
            startService(stop);
            handler.postDelayed(this::refreshUI, 300);
        } else {
            Intent intent = VpnService.prepare(this);
            if (intent != null) {
                startActivityForResult(intent, REQ_VPN);
            } else {
                onActivityResult(REQ_VPN, RESULT_OK, null);
            }
        }
    }

    private void toggleFloatingWindow() {
        if (Build.VERSION.SDK_INT >= 23 && !Settings.canDrawOverlays(this)) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:" + getPackageName()));
            startActivityForResult(intent, REQ_OVERLAY);
            Toast.makeText(this, "请授予悬浮窗权限", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent intent = new Intent(this, FloatingService.class);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
        else startService(intent);
        Toast.makeText(this, "悬浮开关已开启", Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            Intent start = new Intent(this, GuardVpnService.class);
            start.setAction("START");
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(start);
            else startService(start);
            handler.postDelayed(this::refreshUI, 300);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshUI();
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
