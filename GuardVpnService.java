package com.guard;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GuardVpnService extends VpnService {
    public static volatile boolean isAuthorized = false;
    public static volatile boolean isRunning = false;
    public static volatile Set<String> blockedDomains = new HashSet<>();
    public static volatile Set<String> blockedIPs = new HashSet<>();

    private ParcelFileDescriptor vpnInterface;
    private ExecutorService executor;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }
        if (!isRunning && isAuthorized) {
            startVpn();
        }
        return START_STICKY;
    }

    private void startVpn() {
        startForegroundNotify();
        try {
            Builder builder = new Builder();
            builder.setSession("NetGuard Pro");
            builder.addAddress("10.0.0.1", 32);
            builder.addDnsServer("10.0.0.2");
            // 仅接管本地虚拟 DNS，正常流量完全直连不卡网
            builder.addRoute("10.0.0.2", 32);

            // 将服务器下发的黑名单 IP 精准加入 /32 黑洞路由
            for (String ip : blockedIPs) {
                if (ip != null && !ip.isEmpty() && !ip.equals("47.95.119.39") && ip.contains(".")) {
                    try {
                        builder.addRoute(ip, 32);
                    } catch (Exception ignored) {}
                }
            }

            vpnInterface = builder.establish();
            if (vpnInterface == null) return;

            isRunning = true;
            executor = Executors.newCachedThreadPool();
            executor.execute(this::runVpnLoop);
            FloatingService.refreshIfRunning();
        } catch (Exception e) {
            stopVpn();
        }
    }

    private void runVpnLoop() {
        try (FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor())) {
            byte[] buf = new byte[32767];
            while (isRunning) {
                int len = in.read(buf);
                if (len <= 0) continue;

                // 仅处理 IPv4 UDP 53 端口的 DNS 查询，黑名单 IP 的数据包直接丢弃(黑洞)
                int version = (buf[0] >> 4) & 0xF;
                if (version != 4) continue;
                int protocol = buf[9] & 0xFF;
                if (protocol != 17) continue; // 17 = UDP

                int ihl = (buf[0] & 0xF) * 4;
                if (len < ihl + 8) continue;
                int dstPort = ((buf[ihl + 2] & 0xFF) << 8) | (buf[ihl + 3] & 0xFF);
                if (dstPort != 53) continue;

                byte[] packetCopy = new byte[len];
                System.arraycopy(buf, 0, packetCopy, 0, len);
                executor.execute(() -> handleDnsPacket(packetCopy, ihl, out));
            }
        } catch (Exception ignored) {}
    }

    private void handleDnsPacket(byte[] pkt, int ihl, FileOutputStream out) {
        try {
            int dnsOffset = ihl + 8;
            int dnsLen = pkt.length - dnsOffset;
            if (dnsLen <= 12) return;

            String domain = parseDomain(pkt, dnsOffset + 12);
            byte[] dnsResp;

            if (shouldBlockDomain(domain)) {
                // 命中黑名单：0 毫秒本地伪造 NXDOMAIN 阻断
                dnsResp = new byte[dnsLen];
                System.arraycopy(pkt, dnsOffset, dnsResp, 0, dnsLen);
                dnsResp[2] = (byte) 0x81; // QR=1, RD=1
                dnsResp[3] = (byte) 0x83; // RA=1, RCODE=3 (NXDOMAIN)
            } else {
                // 正常域名：通过受保护 Socket 直连阿里 DNS (223.5.5.5) 极速解析
                DatagramSocket socket = new DatagramSocket();
                protect(socket);
                socket.setSoTimeout(3000);
                DatagramPacket req = new DatagramPacket(pkt, dnsOffset, dnsLen, InetAddress.getByName("223.5.5.5"), 53);
                socket.send(req);
                byte[] respBuf = new byte[4096];
                DatagramPacket respPkt = new DatagramPacket(respBuf, respBuf.length);
                socket.receive(respPkt);
                socket.close();
                dnsResp = new byte[respPkt.getLength()];
                System.arraycopy(respBuf, 0, dnsResp, 0, dnsResp.length);
            }

            byte[] ipResp = buildUdpResponse(pkt, ihl, dnsResp);
            synchronized (out) {
                out.write(ipResp);
            }
        } catch (Exception ignored) {}
    }

    private boolean shouldBlockDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase();
        for (String d : blockedDomains) {
            if (lower.equals(d) || lower.endsWith("." + d)) return true;
        }
        return false;
    }

    private String parseDomain(byte[] pkt, int pos) {
        StringBuilder sb = new StringBuilder();
        while (pos < pkt.length) {
            int labelLen = pkt[pos] & 0xFF;
            if (labelLen == 0) break;
            pos++;
            if (pos + labelLen > pkt.length) break;
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(pkt, pos, labelLen));
            pos += labelLen;
        }
        return sb.toString();
    }

    private byte[] buildUdpResponse(byte[] req, int ihl, byte[] payload) {
        int totalLen = 20 + 8 + payload.length;
        byte[] resp = new byte[totalLen];
        resp[0] = 0x45;
        resp[2] = (byte) (totalLen >> 8);
        resp[3] = (byte) totalLen;
        resp[8] = 64;
        resp[9] = 17;
        // 交换源 IP 和目的 IP
        System.arraycopy(req, 16, resp, 12, 4);
        System.arraycopy(req, 12, resp, 16, 4);
        // 计算 IPv4 校验和
        int sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += ((resp[i] & 0xFF) << 8) | (resp[i + 1] & 0xFF);
        }
        while ((sum >> 16) > 0) sum = (sum & 0xFFFF) + (sum >> 16);
        int checksum = ~sum & 0xFFFF;
        resp[10] = (byte) (checksum >> 8);
        resp[11] = (byte) checksum;

        // 交换 UDP 源端口和目的端口
        resp[20] = req[ihl + 2];
        resp[21] = req[ihl + 3];
        resp[22] = req[ihl];
        resp[23] = req[ihl + 1];
        int udpLen = 8 + payload.length;
        resp[24] = (byte) (udpLen >> 8);
        resp[25] = (byte) udpLen;
        System.arraycopy(payload, 0, resp, 28, payload.length);
        return resp;
    }

    private void stopVpn() {
        isRunning = false;
        try {
            if (vpnInterface != null) vpnInterface.close();
        } catch (Exception ignored) {}
        if (executor != null) executor.shutdownNow();
        FloatingService.refreshIfRunning();
        stopForeground(true);
        stopSelf();
    }

    private void startForegroundNotify() {
        String cid = "guard_vpn_ch";
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(cid, "拦截服务", NotificationManager.IMPORTANCE_LOW);
            getSystemService(NotificationManager.class).createNotificationChannel(ch);
            startForeground(1, new Notification.Builder(this, cid)
                    .setContentTitle("NetGuard Pro 运行中")
                    .setContentText("本地零延迟拦截已开启")
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .build());
        } else {
            startForeground(1, new Notification.Builder(this)
                    .setContentTitle("NetGuard Pro 运行中")
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .build());
        }
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
