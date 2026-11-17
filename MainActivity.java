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
import android.view.Gravity;
import android.view.View;
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
import java.util.HashSet;
import java.util.Set;

public class MainActivity extends Activity {
    private static final String SERVER_URL = "http://47.95.119.39:8899/verify";
    private static final int REQ_VPN = 1001;
    private static final int REQ_OVERLAY = 1002;

    private TextView tvStatus, tvRuleInfo, tvExpire;
    private EditText etKey;
    private Button btnPower, btnVerify, btnFloat;
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

        // 顶部霓虹标题
        TextView title = new TextView(this);
        title.setText("NETGUARD PRO");
        title.setTextColor(Color.parseColor("#00E5FF"));
        title.setTextSize(26);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setLetterSpacing(0.15f);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("云端极速拦截引擎 · 零延迟直连");
        sub.setTextColor(Color.parseColor("#64748B"));
        sub.setTextSize(12);
        sub.setPadding(0, dp(4), 0, dp(28));
        root.addView(sub);

        // 核心圆形开关按钮
        btnPower = new Button(this);
        btnPower.setText("未激活");
        btnPower.setTextColor(Color.WHITE);
        btnPower.setTextSize(18);
        btnPower.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams powerLp = new LinearLayout.LayoutParams(dp(150), dp(150));
        powerLp.bottomMargin = dp(16);
        btnPower.setLayoutParams(powerLp);
        btnPower.setOnClickListener(v -> toggleVpn());
        root.addView(btnPower);

        tvStatus = new TextView(this);
        tvStatus.setText("状态：等待 10 位卡密激活");
        tvStatus.setTextColor(Color.parseColor("#94A3B8"));
        tvStatus.setTextSize(14);
        tvStatus.setPadding(0, 0, 0, dp(24));
        root.addView(tvStatus);

        // 卡片 1：卡密激活区
        LinearLayout cardAuth = createCard();
        TextView lbKey = new TextView(this);
        lbKey.setText("授权卡密 (10位)");
        lbKey.setTextColor(Color.parseColor("#E2E8F0"));
        lbKey.setTextSize(14);
        lbKey.setTypeface(Typeface.DEFAULT_BOLD);
        cardAuth.addView(lbKey);

        etKey = new EditText(this);
        etKey.setHint("输入 10 位卡密");
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
        btnVerify.setText("验证卡密并同步云端规则");
        btnVerify.setTextColor(Color.WHITE);
        btnVerify.setTextSize(14);
        btnVerify.setTypeface(Typeface.DEFAULT_BOLD);
        btnVerify.setBackground(roundBg("#2563EB", "#3B82F6", dp(10)));
        btnVerify.setOnClickListener(v -> verifyKey(etKey.getText().toString().trim().toUpperCase(), false));
        cardAuth.addView(btnVerify);

        tvExpire = new TextView(this);
        tvExpire.setText("有效期：未验证");
        tvExpire.setTextColor(Color.parseColor("#64748B"));
        tvExpire.setTextSize(12);
        tvExpire.setPadding(0, dp(10), 0, 0);
        cardAuth.addView(tvExpire);

        tvRuleInfo = new TextView(this);
        tvRuleInfo.setText("云端规则：0 条域名 / 0 条 IP");
        tvRuleInfo.setTextColor(Color.parseColor("#38BDF8"));
        tvRuleInfo.setTextSize(12);
        tvRuleInfo.setPadding(0, dp(4), 0, 0);
        cardAuth.addView(tvRuleInfo);
        root.addView(cardAuth);

        // 卡片 2：悬浮球控制区
        LinearLayout cardFloat = createCard();
        btnFloat = new Button(this);
        btnFloat.setText("开启桌面悬浮开关");
        btnFloat.setTextColor(Color.WHITE);
        btnFloat.setTextSize(14);
        btnFloat.setTypeface(Typeface.DEFAULT_BOLD);
        btnFloat.setBackground(roundBg("#0F766E", "#14B8A6", dp(10)));
        btnFloat.setOnClickListener(v -> toggleFloatingWindow());
        cardFloat.addView(btnFloat);

        TextView tip = new TextView(this);
        tip.setText("提示：长按悬浮球 1 秒可隐藏至通知栏，点击通知栏随时呼出");
        tip.setTextColor(Color.parseColor("#64748B"));
        tip.setTextSize(11);
        tip.setPadding(0, dp(10), 0, 0);
        cardFloat.addView(tip);
        root.addView(cardFloat);

        scroll.addView(root);
        setContentView(scroll);
        refreshUI();
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
            tvStatus.setText("状态：请先验证 10 位卡密");
        } else if (GuardVpnService.isRunning) {
            circle.setColor(Color.parseColor("#064E3B"));
            circle.setStroke(dp(4), Color.parseColor("#10B981"));
            btnPower.setText("拦截已开启");
            tvStatus.setText("状态：本地零延迟拦截运行中");
        } else {
            circle.setColor(Color.parseColor("#172554"));
            circle.setStroke(dp(4), Color.parseColor("#3B82F6"));
            btnPower.setText("点击开启");
            tvStatus.setText("状态：已授权（待机中）");
        }
        btnPower.setBackground(circle);
        tvRuleInfo.setText("云端规则：" + GuardVpnService.blockedDomains.size() + " 条域名 / " + GuardVpnService.blockedIPs.size() + " 条 IP");
    }

    private void verifyKey(String key, boolean silent) {
        if (key.length() != 10) {
            if (!silent) Toast.makeText(this, "请输入 10 位数卡密", Toast.LENGTH_SHORT).show();
            return;
        }
        btnVerify.setText("云端同步中...");
        new Thread(() -> {
            try {
                String udid = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
                URL url = new URL(SERVER_URL + "?key=" + key + "&udid=" + udid);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(6000);
                conn.setReadTimeout(6000);
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
                br.close();

                JSONObject json = new JSONObject(sb.toString());
                int code = json.optInt("code", 500);
                String msg = json.optString("msg", "验证完成");

                if (code == 200) {
                    Set<String> domains = new HashSet<>();
                    JSONArray dArr = json.optJSONArray("domains");
                    if (dArr != null) {
                        for (int i = 0; i < dArr.length(); i++) domains.add(dArr.getString(i).toLowerCase().trim());
                    }
                    Set<String> ips = new HashSet<>();
                    JSONArray iArr = json.optJSONArray("ips");
                    if (iArr != null) {
                        for (int i = 0; i < iArr.length(); i++) ips.add(iArr.getString(i).trim());
                    }
                    GuardVpnService.blockedDomains = domains;
                    GuardVpnService.blockedIPs = ips;
                    GuardVpnService.isAuthorized = true;
                    sp.edit().putString("license_key", key).apply();

                    handler.post(() -> {
                        btnVerify.setText("重新同步云端规则");
                        tvExpire.setText(msg);
                        refreshUI();
                        if (!silent) Toast.makeText(this, "激活成功！", Toast.LENGTH_SHORT).show();
                    });
                } else {
                    GuardVpnService.isAuthorized = false;
                    handler.post(() -> {
                        btnVerify.setText("验证卡密并同步云端规则");
                        tvExpire.setText("验证失败：" + msg);
                        refreshUI();
                        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
                    });
                }
            } catch (Exception e) {
                handler.post(() -> {
                    btnVerify.setText("验证卡密并同步云端规则");
                    if (!silent) Toast.makeText(this, "连接服务器失败", Toast.LENGTH_SHORT).show();
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
        Toast.makeText(this, "悬浮球已开启", Toast.LENGTH_SHORT).show();
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
