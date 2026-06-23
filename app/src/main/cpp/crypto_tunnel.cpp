// ARQUIVO 5: /app/src/main/cpp/crypto_tunnel.cpp
#include "crypto_tunnel.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <android/log.h>
#include <cstring>

#define LOG_TAG "CryptoTunnel"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

MbedtlsContext::MbedtlsContext() {
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_net_init(&server_fd);
}

MbedtlsContext::~MbedtlsContext() {
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&server_fd);
}

CryptoTunnel::CryptoTunnel() = default;

CryptoTunnel::~CryptoTunnel() {
    close();
}

bool CryptoTunnel::connect(const HttpPayloadConfig& config) {
    currentConfig_ = config;
    ctx_ = std::make_unique<MbedtlsContext>();
    
    // Passo 1: Conexão TCP de nível inferior
    if (!establishSocketConnection()) {
        LOGE("Failed to establish socket connection");
        return false;
    }
    
    // Passo 2: Se usando proxy, realiza handshake HTTP CONNECT
    if (config.useProxy) {
        if (!performHttpProxyHandshake()) {
            LOGE("Failed HTTP proxy handshake");
            return false;
        }
    }
    
    // Passo 3: Configuração mbedTLS e handshake SSL
    if (!setupMbedtls()) {
        LOGE("Failed mbedTLS setup");
        return false;
    }
    
    if (!performSslHandshake()) {
        LOGE("Failed SSL handshake");
        return false;
    }
    
    connected_ = true;
    LOGD("Crypto tunnel established successfully");
    return true;
}

bool CryptoTunnel::establishSocketConnection() {
    const char* host = currentConfig_.useProxy ? currentConfig_.proxyHost.c_str() 
                                               : currentConfig_.remoteHost.c_str();
    int port = currentConfig_.useProxy ? currentConfig_.proxyPort 
                                      : currentConfig_.remotePort;
    
    struct hostent* server = gethostbyname(host);
    if (!server) {
        LOGE("Failed to resolve hostname: %s", host);
        return false;
    }
    
    sockFd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd_ < 0) {
        LOGE("Failed to create socket");
        return false;
    }
    
    // Configurações de socket para baixa latência móvel
    int flag = 1;
    setsockopt(sockFd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    // Timeout de conexão
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(sockFd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sockFd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    memcpy(&serverAddr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    if (::connect(sockFd_, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        LOGE("Failed to connect to %s:%d", host, port);
        close();
        return false;
    }
    
    LOGD("Socket connected to %s:%d", host, port);
    return true;
}

bool CryptoTunnel::performHttpProxyHandshake() {
    HttpPreprocessor preprocessor;
    std::string payload = preprocessor.generateProxyPayload(currentConfig_);
    
    LOGD("Sending proxy payload:\n%s", payload.c_str());
    
    ssize_t sent = send(sockFd_, payload.c_str(), payload.length(), 0);
    if (sent < 0) {
        LOGE("Failed to send proxy payload");
        return false;
    }
    
    // Recebe resposta do proxy
    char buffer[4096];
    ssize_t received = recv(sockFd_, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        LOGE("Failed to receive proxy response");
        return false;
    }
    buffer[received] = '\0';
    
    std::string response(buffer);
    LOGD("Proxy response:\n%s", response.c_str());
    
    if (!preprocessor.validateProxyResponse(response)) {
        LOGE("Invalid proxy response");
        return false;
    }
    
    LOGD("HTTP Proxy handshake successful");
    return true;
}

bool CryptoTunnel::setupMbedtls() {
    const char* pers = "vpn_tunnel_ssl";
    
    int ret = mbedtls_ctr_drbg_seed(&ctx_->ctr_drbg, mbedtls_entropy_func, 
                                    &ctx_->entropy,
                                    reinterpret_cast<const unsigned char*>(pers), 
                                    strlen(pers));
    if (ret != 0) {
        LOGE("Failed to seed RNG: %d", ret);
        return false;
    }
    
    ret = mbedtls_ssl_config_defaults(&ctx_->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        LOGE("Failed to config defaults: %d", ret);
        return false;
    }
    
    // Configura verificação de certificado (modo permissivo para bypass)
    mbedtls_ssl_conf_authmode(&ctx_->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ctx_->conf, nullptr, nullptr);
    
    // Configura RNG
    mbedtls_ssl_conf_rng(&ctx_->conf, mbedtls_ctr_drbg_random, &ctx_->ctr_drbg);
    
    // Configurações de SSL otimizadas para redes móveis
    mbedtls_ssl_conf_max_version(&ctx_->conf, MBEDTLS_SSL_MAJOR_VERSION_3, 
                                 MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_min_version(&ctx_->conf, MBEDTLS_SSL_MAJOR_VERSION_3, 
                                 MBEDTLS_SSL_MINOR_VERSION_1);
    
    // Ciphersuites permitidas (compatíveis com operadoras)
    static const int ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(&ctx_->conf, ciphersuites);
    
    ret = mbedtls_ssl_setup(&ctx_->ssl, &ctx_->conf);
    if (ret != 0) {
        LOGE("Failed SSL setup: %d", ret);
        return false;
    }
    
    // Configura SNI (Server Name Indication) - crucial para bypass DPI
    std::string sniHost = currentConfig_.sniHostname.empty() ? 
                          currentConfig_.remoteHost : currentConfig_.sniHostname;
    
    ret = mbedtls_ssl_set_hostname(&ctx_->ssl, sniHost.c_str());
    if (ret != 0) {
        LOGE("Failed to set SNI hostname: %d", ret);
        return false;
    }
    
    // Configura callbacks de I/O para usar nosso socket
    mbedtls_ssl_set_bio(&ctx_->ssl, &sockFd_,
                        [](void* ctx, const unsigned char* buf, size_t len) -> int {
                            int fd = *static_cast<int*>(ctx);
                            return send(fd, buf, len, 0);
                        },
                        [](void* ctx, unsigned char* buf, size_t len) -> int {
                            int fd = *static_cast<int*>(ctx);
                            return recv(fd, buf, len, 0);
                        },
                        nullptr);
    
    LOGD("mbedTLS configured with SNI: %s", sniHost.c_str());
    return true;
}

bool CryptoTunnel::performSslHandshake() {
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ctx_->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char error_buf[256];
            mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            LOGE("SSL handshake failed: %s (0x%04x)", error_buf, ret);
            return false;
        }
    }
    
    LOGD("SSL handshake completed, cipher: %s", mbedtls_ssl_get_ciphersuite(&ctx_->ssl));
    return true;
}

ssize_t CryptoTunnel::send(const uint8_t* data, size_t len) {
    if (!connected_ || !ctx_) return -1;
    
    size_t sent = 0;
    while (sent < len) {
        int ret = mbedtls_ssl_write(&ctx_->ssl, data + sent, len - sent);
        if (ret > 0) {
            sent += ret;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE || 
                   ret == MBEDTLS_ERR_SSL_WANT_READ) {
            continue;
        } else {
            LOGE("SSL write error: %d", ret);
            return -1;
        }
    }
    return sent;
}

ssize_t CryptoTunnel::receive(uint8_t* buffer, size_t len) {
    if (!connected_ || !ctx_) return -1;
    
    int ret = mbedtls_ssl_read(&ctx_->ssl, buffer, len);
    if (ret > 0) {
        return ret;
    } else if (ret == MBEDTLS_ERR_SSL_WANT_READ || 
               ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0; // Não bloqueante
    } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        LOGD("Peer closed connection");
        connected_ = false;
        return 0;
    } else {
        LOGE("SSL read error: %d", ret);
        return -1;
    }
}

bool CryptoTunnel::isConnected() const {
    return connected_ && ctx_ != nullptr;
}

void CryptoTunnel::close() {
    if (ctx_) {
        mbedtls_ssl_close_notify(&ctx_->ssl);
    }
    if (sockFd_ >= 0) {
        ::close(sockFd_);
        sockFd_ = -1;
    }
    connected_ = false;
    ctx_.reset();
}
