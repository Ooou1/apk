package com.guard;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.TextView;
import android.widget.Toast;

public class FloatingService extends Service {
    private static FloatingService instance;
    private WindowManager wm;
    private TextView floatBtn;
    private WindowManager.LayoutParams params;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean isLongPressed = false;

    public static void refreshIfRunning() {
        if (instance != null) {
            instance.handler.post(() -> instance.updateStyle());
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        startNotify();
        createFloatingView();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "SHOW".equals(intent.getAction()) && floatBtn != null) {
            floatBtn.setVisibility(View.VISIBLE);
        }
        updateStyle();
        return START_STICKY;
    }

    private void createFloatingView() {
        wm = (WindowManager) getSystemService(WINDOW_SERVICE);
        floatBtn = new TextView(this);
        floatBtn.setTextColor(Color.WHITE);
        floatBtn.setTextSize(13);
        floatBtn.setTypeface(Typeface.DEFAULT_BOLD);
        floatBtn.setGravity(Gravity.CENTER);
        int pH = dp(14), pV = dp(8);
        floatBtn.setPadding(pH, pV, pH, pV);

        int type = Build.VERSION.SDK_INT >= 26
                ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                : WindowManager.LayoutParams.TYPE_PHONE;

        params = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                type,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
                PixelFormat.TRANSLUCENT);
        params.gravity = Gravity.TOP | Gravity.START;
        params.x = dp(20);
        params.y = dp(180);

        floatBtn.setOnTouchListener(new View.OnTouchListener() {
            int initX, initY;
            float touchX, touchY;
            boolean moved;
            final Runnable longPressTask = () -> {
                isLongPressed = true;
                floatBtn.setVisibility(View.GONE);
                Toast.makeText(FloatingService.this, "悬浮球已隐藏，点击通知栏可恢复", Toast.LENGTH_SHORT).show();
            };

            @Override
            public boolean onTouch(View v, MotionEvent e) {
                switch (e.getAction()) {
                    case MotionEvent.ACTION_DOWN:
                        initX = params.x;
                        initY = params.y;
                        touchX = e.getRawX();
                        touchY = e.getRawY();
                        moved = false;
                        isLongPressed = false;
                        handler.postDelayed(longPressTask, 900);
                        return true;
                    case MotionEvent.ACTION_MOVE:
                        int dx = (int) (e.getRawX() - touchX);
                        int dy = (int) (e.getRawY() - touchY);
                        if (Math.abs(dx) > 10 || Math.abs(dy) > 10) {
                            moved = true;
                            handler.removeCallbacks(longPressTask);
                        }
                        params.x = initX + dx;
                        params.y = initY + dy;
                        wm.updateViewLayout(floatBtn, params);
                        return true;
                    case MotionEvent.ACTION_UP:
                        handler.removeCallbacks(longPressTask);
                        if (!moved && !isLongPressed) {
                            toggleVpnFromFloat();
                        }
                        return true;
                }
                return false;
            }
        });

        updateStyle();
        wm.addView(floatBtn, params);
    }

    private void toggleVpnFromFloat() {
        if (!GuardVpnService.isAuthorized) {
            Toast.makeText(this, "请先打开软件激活卡密", Toast.LENGTH_SHORT).show();
            return;
        }
        Intent intent = new Intent(this, GuardVpnService.class);
        intent.setAction(GuardVpnService.isRunning ? "STOP" : "START");
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
        else startService(intent);
    }

    private void updateStyle() {
        if (floatBtn == null) return;
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(20));
        if (GuardVpnService.isRunning) {
            bg.setColor(Color.parseColor("#E6DC2626"));
            bg.setStroke(dp(1), Color.parseColor("#FCA5A5"));
            floatBtn.setText("● 拦截: 开启");
        } else {
            bg.setColor(Color.parseColor("#E6059669"));
            bg.setStroke(dp(1), Color.parseColor("#6EE7B7"));
            floatBtn.setText("○ 拦截: 关闭");
        }
        floatBtn.setBackground(bg);
    }

    private void startNotify() {
        String cid = "guard_float_ch";
        Intent showIntent = new Intent(this, FloatingService.class);
        showIntent.setAction("SHOW");
        int piFlags = Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
        PendingIntent pi = PendingIntent.getService(this, 0, showIntent, piFlags);

        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(cid, "悬浮球控制", NotificationManager.IMPORTANCE_LOW);
            getSystemService(NotificationManager.class).createNotificationChannel(ch);
            startForeground(2, new Notification.Builder(this, cid)
                    .setContentTitle("NetGuard Pro 悬浮球")
                    .setContentText("点击此处可随时恢复/显示悬浮球")
                    .setSmallIcon(android.R.drawable.ic_menu_view)
                    .setContentIntent(pi)
                    .build());
        } else {
            startForeground(2, new Notification.Builder(this)
                    .setContentTitle("NetGuard Pro 悬浮球")
                    .setContentText("点击此处可随时恢复/显示悬浮球")
                    .setSmallIcon(android.R.drawable.ic_menu_view)
                    .setContentIntent(pi)
                    .build());
        }
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    @Override
    public void onDestroy() {
        instance = null;
        if (wm != null && floatBtn != null) wm.removeView(floatBtn);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
