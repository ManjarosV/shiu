// ARQUIVO 1: /app/src/main/java/com/injector/vpn/MyVpnService.kt
package com.injector.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class MyVpnService : VpnService() {
    companion object {
        private const val TAG = "MyVpnService"
        private const val VPN_MTU = 1500
        private const val NOTIFICATION_ID = 1337
        private const val CHANNEL_ID = "vpn_channel"
        
        init {
            System.loadLibrary("netcore")
        }
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    private val bytesSent = AtomicLong(0)
    private val bytesReceived = AtomicLong(0)
    private var nativeThread: Thread? = null
    
    // Configurações injetáveis via Intent
    data class VpnConfig(
        val remoteHost: String,
        val remotePort: Int,
        val payloadTemplate: String,
        val sniHostname: String,
        val useProxy: Boolean,
        val proxyHost: String?,
        val proxyPort: Int,
        val userAgent: String
    )
    
    private var currentConfig: VpnConfig? = null
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "START" -> {
                val config = VpnConfig(
                    remoteHost = intent.getStringExtra("remote_host") ?: "127.0.0.1",
                    remotePort = intent.getIntExtra("remote_port", 443),
                    payloadTemplate = intent.getStringExtra("payload_template") ?: "GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]",
                    sniHostname = intent.getStringExtra("sni_hostname") ?: "www.google.com",
                    useProxy = intent.getBooleanExtra("use_proxy", false),
                    proxyHost = intent.getStringExtra("proxy_host"),
                    proxyPort = intent.getIntExtra("proxy_port", 8080),
                    userAgent = intent.getStringExtra("user_agent") ?: "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36"
                )
                startVpn(config)
            }
            "STOP" -> stopVpn()
        }
        return START_NOT_STICKY
    }
    
    private fun startVpn(config: VpnConfig) {
        if (isRunning.get()) return
        
        currentConfig = config
        
        val builder = Builder().apply {
            setMtu(VPN_MTU)
            addAddress("10.0.0.2", 24)
            addAddress("fd00:1:2:3::2", 64)
            addRoute("0.0.0.0", 0)
            addRoute("::", 0)
            addDnsServer("8.8.8.8")
            addDnsServer("8.8.4.4")
            addDnsServer("2001:4860:4860::8888")
            establish()
        }
        
        vpnInterface = builder.establish()
        vpnInterface?.let { pfd ->
            isRunning.set(true)
            
            // Inicializa callbacks JNI
            initNativeCallbacks(this)
            
            // Passa configurações para o nativo
            setNativeConfig(
                config.remoteHost,
                config.remotePort,
                config.payloadTemplate,
                config.sniHostname,
                config.useProxy,
                config.proxyHost ?: "",
                config.proxyPort,
                config.userAgent
            )
            
            // Inicia processamento nativo em thread separada
            nativeThread = Thread {
                val fd = pfd.fd
                Log.d(TAG, "Starting native tunnel with fd: $fd")
                startNativeTunnel(fd)
            }.apply { start() }
            
            startForeground(NOTIFICATION_ID, buildNotification("Conectado - ${config.remoteHost}"))
        }
    }
    
    private fun stopVpn() {
        isRunning.set(false)
        stopNativeTunnel()
        nativeThread?.join(5000)
        nativeThread = null
        
        vpnInterface?.close()
        vpnInterface = null
        
        stopForeground(true)
        stopSelf()
    }
    
    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
    
    override fun onRevoke() {
        Log.w(TAG, "VPN revoked by user or system")
        stopVpn()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }
    
    private fun buildNotification(content: String) = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("HTTP Injector VPN")
        .setContentText(content)
        .setSmallIcon(android.R.drawable.ic_secure)
        .setOngoing(true)
        .build()
    
    // Callbacks chamados pelo código nativo via JNI
    fun onNativeStatsUpdate(sent: Long, received: Long) {
        bytesSent.set(sent)
        bytesReceived.set(received)
        // Atualizar UI via broadcast ou LiveData
    }
    
    fun onNativeLog(message: String) {
        Log.d(TAG, "Native: $message")
    }
    
    fun onNativeError(error: String) {
        Log.e(TAG, "Native Error: $error")
        stopVpn()
    }
    
    // Funções JNI nativas
    private external fun initNativeCallbacks(service: MyVpnService)
    private external fun setNativeConfig(
        remoteHost: String,
        remotePort: Int,
        payloadTemplate: String,
        sniHostname: String,
        useProxy: Boolean,
        proxyHost: String,
        proxyPort: Int,
        userAgent: String
    )
    private external fun startNativeTunnel(fd: Int)
    private external fun stopNativeTunnel()
}
