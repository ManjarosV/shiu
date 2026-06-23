// ARQUIVO 2: /app/src/main/cpp/jni_bridge.cpp
#include <jni.h>
#include <android/log.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <atomic>

#include "core.hpp"

#define LOG_TAG "JNI_Bridge"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Estrutura global para manter contexto JNI
struct JniContext {
    JavaVM* vm = nullptr;
    jobject serviceRef = nullptr;
    jmethodID statsMethodId = nullptr;
    jmethodID logMethodId = nullptr;
    jmethodID errorMethodId = nullptr;
    std::mutex mutex;
};

static JniContext g_context;
static std::unique_ptr<VpnCore> g_vpnCore;
static std::atomic<bool> g_running{false};

// Configurações globais recebidas do Java
struct NativeConfig {
    std::string remoteHost;
    int remotePort = 443;
    std::string payloadTemplate;
    std::string sniHostname;
    bool useProxy = false;
    std::string proxyHost;
    int proxyPort = 8080;
    std::string userAgent;
};

static NativeConfig g_config;

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("JNI_OnLoad called");
    g_context.vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_injector_vpn_MyVpnService_initNativeCallbacks(JNIEnv* env, jobject thiz, jobject service) {
    std::lock_guard<std::mutex> lock(g_context.mutex);
    
    if (g_context.serviceRef) {
        env->DeleteGlobalRef(g_context.serviceRef);
    }
    
    g_context.serviceRef = env->NewGlobalRef(service);
    jclass serviceClass = env->GetObjectClass(g_context.serviceRef);
    
    g_context.statsMethodId = env->GetMethodID(serviceClass, "onNativeStatsUpdate", "(JJ)V");
    g_context.logMethodId = env->GetMethodID(serviceClass, "onNativeLog", "(Ljava/lang/String;)V");
    g_context.errorMethodId = env->GetMethodID(serviceClass, "onNativeError", "(Ljava/lang/String;)V");
    
    env->DeleteLocalRef(serviceClass);
    LOGD("Native callbacks initialized");
}

JNIEXPORT void JNICALL
Java_com_injector_vpn_MyVpnService_setNativeConfig(
    JNIEnv* env, jobject thiz,
    jstring remoteHost, jint remotePort,
    jstring payloadTemplate, jstring sniHostname,
    jboolean useProxy, jstring proxyHost, jint proxyPort,
    jstring userAgent
) {
    const char* hostStr = env->GetStringUTFChars(remoteHost, nullptr);
    const char* payloadStr = env->GetStringUTFChars(payloadTemplate, nullptr);
    const char* sniStr = env->GetStringUTFChars(sniHostname, nullptr);
    const char* proxyStr = env->GetStringUTFChars(proxyHost, nullptr);
    const char* uaStr = env->GetStringUTFChars(userAgent, nullptr);
    
    g_config.remoteHost = hostStr;
    g_config.remotePort = remotePort;
    g_config.payloadTemplate = payloadStr;
    g_config.sniHostname = sniStr;
    g_config.useProxy = useProxy;
    g_config.proxyHost = proxyStr;
    g_config.proxyPort = proxyPort;
    g_config.userAgent = uaStr;
    
    env->ReleaseStringUTFChars(remoteHost, hostStr);
    env->ReleaseStringUTFChars(payloadTemplate, payloadStr);
    env->ReleaseStringUTFChars(sniHostname, sniStr);
    env->ReleaseStringUTFChars(proxyHost, proxyStr);
    env->ReleaseStringUTFChars(userAgent, uaStr);
    
    LOGD("Native config set: host=%s, port=%d, proxy=%d", 
         g_config.remoteHost.c_str(), g_config.remotePort, g_config.useProxy);
}

// Callbacks para o Core C++ chamar de volta o Java
class JniCallbacks : public CoreCallbacks {
public:
    void updateStats(uint64_t sent, uint64_t received) override {
        std::lock_guard<std::mutex> lock(g_context.mutex);
        if (!g_context.vm || !g_context.serviceRef) return;
        
        JNIEnv* env;
        jint attachResult = g_context.vm->AttachCurrentThread(&env, nullptr);
        if (attachResult != JNI_OK) return;
        
        env->CallVoidMethod(g_context.serviceRef, g_context.statsMethodId, 
                           static_cast<jlong>(sent), static_cast<jlong>(received));
        
        if (attachResult == JNI_EDETACHED) {
            g_context.vm->DetachCurrentThread();
        }
    }
    
    void logMessage(const std::string& msg) override {
        std::lock_guard<std::mutex> lock(g_context.mutex);
        if (!g_context.vm || !g_context.serviceRef) return;
        
        JNIEnv* env;
        jint attachResult = g_context.vm->AttachCurrentThread(&env, nullptr);
        if (attachResult != JNI_OK) return;
        
        jstring jmsg = env->NewStringUTF(msg.c_str());
        env->CallVoidMethod(g_context.serviceRef, g_context.logMethodId, jmsg);
        env->DeleteLocalRef(jmsg);
        
        if (attachResult == JNI_EDETACHED) {
            g_context.vm->DetachCurrentThread();
        }
    }
    
    void reportError(const std::string& error) override {
        std::lock_guard<std::mutex> lock(g_context.mutex);
        if (!g_context.vm || !g_context.serviceRef) return;
        
        JNIEnv* env;
        jint attachResult = g_context.vm->AttachCurrentThread(&env, nullptr);
        if (attachResult != JNI_OK) return;
        
        jstring jerror = env->NewStringUTF(error.c_str());
        env->CallVoidMethod(g_context.serviceRef, g_context.errorMethodId, jerror);
        env->DeleteLocalRef(jerror);
        
        if (attachResult == JNI_EDETACHED) {
            g_context.vm->DetachCurrentThread();
        }
    }
};

JNIEXPORT void JNICALL
Java_com_injector_vpn_MyVpnService_startNativeTunnel(JNIEnv* env, jobject thiz, jint fd) {
    LOGD("Starting native tunnel with fd=%d", fd);
    g_running = true;
    
    auto callbacks = std::make_unique<JniCallbacks>();
    
    TunnelConfig config;
    config.tunFd = fd;
    config.remoteHost = g_config.remoteHost;
    config.remotePort = g_config.remotePort;
    config.payloadTemplate = g_config.payloadTemplate;
    config.sniHostname = g_config.sniHostname;
    config.useProxy = g_config.useProxy;
    config.proxyHost = g_config.proxyHost;
    config.proxyPort = g_config.proxyPort;
    config.userAgent = g_config.userAgent;
    
    g_vpnCore = std::make_unique<VpnCore>(std::move(callbacks), config);
    g_vpnCore->run();
}

JNIEXPORT void JNICALL
Java_com_injector_vpn_MyVpnService_stopNativeTunnel(JNIEnv* env, jobject thiz) {
    LOGD("Stopping native tunnel");
    g_running = false;
    if (g_vpnCore) {
        g_vpnCore->stop();
        g_vpnCore.reset();
    }
}

} // extern "C"
