// ARQUIVO 3: /app/src/main/cpp/core.cpp
#include "core.hpp"
#include "preprocessor.hpp"
#include "crypto_tunnel.hpp"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <android/log.h>
#include <cstring>
#include <map>
#include <mutex>

#define LOG_TAG "VpnCore"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Gerenciador de conexões ativas
class VpnCore::ConnectionManager {
public:
    struct Connection {
        int clientFd = -1;
        int remoteFd = -1;
        uint32_t srcAddr = 0;
        uint32_t dstAddr = 0;
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;
        bool handshakeComplete = false;
        std::unique_ptr<CryptoTunnel> crypto;
        std::vector<uint8_t> pendingData;
        std::mutex connMutex;
    };
    
    std::map<uint64_t, std::unique_ptr<Connection>> connections;
    std::mutex mutex;
    
    uint64_t makeKey(uint32_t srcAddr, uint16_t srcPort, uint32_t dstAddr, uint16_t dstPort) {
        return (static_cast<uint64_t>(srcAddr) << 32) | (static_cast<uint64_t>(srcPort) << 16) | dstPort;
    }
    
    Connection* findOrCreate(uint32_t srcAddr, uint16_t srcPort, uint32_t dstAddr, uint16_t dstPort) {
        std::lock_guard<std::mutex> lock(mutex);
        uint64_t key = makeKey(srcAddr, srcPort, dstAddr, dstPort);
        auto it = connections.find(key);
        if (it == connections.end()) {
            auto conn = std::make_unique<Connection>();
            conn->srcAddr = srcAddr;
            conn->dstAddr = dstAddr;
            conn->srcPort = srcPort;
            conn->dstPort = dstPort;
            auto* ptr = conn.get();
            connections[key] = std::move(conn);
            return ptr;
        }
        return it->second.get();
    }
    
    void remove(uint32_t srcAddr, uint16_t srcPort, uint32_t dstAddr, uint16_t dstPort) {
        std::lock_guard<std::mutex> lock(mutex);
        uint64_t key = makeKey(srcAddr, srcPort, dstAddr, dstPort);
        connections.erase(key);
    }
};

VpnCore::VpnCore(std::unique_ptr<CoreCallbacks> callbacks, const TunnelConfig& config)
    : callbacks_(std::move(callbacks)), config_(config), buffer_(BUFFER_SIZE) {
    connManager_ = std::make_unique<ConnectionManager>();
}

VpnCore::~VpnCore() {
    stop();
}

void VpnCore::run() {
    if (config_.tunFd < 0) {
        callbacks_->reportError("Invalid TUN file descriptor");
        return;
    }
    
    // Configura non-blocking no TUN
    int flags = fcntl(config_.tunFd, F_GETFL, 0);
    fcntl(config_.tunFd, F_SETFL, flags | O_NONBLOCK);
    
    // Cria epoll
    epollFd_ = epoll_create1(0);
    if (epollFd_ < 0) {
        callbacks_->reportError("Failed to create epoll");
        return;
    }
    
    // Adiciona TUN fd ao epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = config_.tunFd;
    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, config_.tunFd, &ev) < 0) {
        callbacks_->reportError("Failed to add TUN to epoll");
        return;
    }
    
    running_ = true;
    callbacks_->logMessage("VPN Core started");
    
    struct epoll_event events[32];
    
    while (running_) {
        int nfds = epoll_wait(epollFd_, events, 32, 100);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == config_.tunFd) {
                processTunPacket();
            }
        }
        
        // Atualiza estatísticas periodicamente
        static int statCounter = 0;
        if (++statCounter % 100 == 0) {
            callbacks_->updateStats(bytesSent_.load(), bytesReceived_.load());
        }
    }
    
    close(epollFd_);
    callbacks_->logMessage("VPN Core stopped");
}

void VpnCore::stop() {
    running_ = false;
}

void VpnCore::processTunPacket() {
    ssize_t len = read(config_.tunFd, buffer_.data(), buffer_.size());
    if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGE("TUN read error: %s", strerror(errno));
        }
        return;
    }
    
    if (len < 1) return;
    
    uint8_t version = (buffer_[0] >> 4) & 0x0F;
    
    if (version == 4) {
        handleIPv4Packet(buffer_.data(), len);
    } else if (version == 6) {
        handleIPv6Packet(buffer_.data(), len);
    }
}

void VpnCore::handleIPv4Packet(const uint8_t* data, size_t len) {
    if (len < sizeof(IPv4Header)) return;
    
    const auto* ipHeader = reinterpret_cast<const IPv4Header*>(data);
    size_t ipHeaderLen = ipHeader->ihl * 4;
    size_t payloadLen = ntohs(ipHeader->tot_len) - ipHeaderLen;
    
    if (len < ipHeaderLen + payloadLen) return;
    
    const uint8_t* payload = data + ipHeaderLen;
    
    switch (ipHeader->protocol) {
        case 6: // TCP
            handleTCPPacket(data, len, ipHeader);
            break;
        case 17: // UDP
            handleUDPPacket(data, len, ipHeader);
            break;
        default:
            // Encaminha outros protocolos diretamente (simplificado)
            break;
    }
}

void VpnCore::handleIPv6Packet(const uint8_t* data, size_t len) {
    if (len < sizeof(IPv6Header)) return;
    
    const auto* ipHeader = reinterpret_cast<const IPv6Header*>(data);
    // Implementação IPv6 similar ao IPv4
    // Por simplicidade, encaminha para tratamento de extensoes se necessário
}

void VpnCore::handleTCPPacket(const uint8_t* ipData, size_t ipLen, const IPv4Header* ipHeader) {
    size_t ipHeaderLen = ipHeader->ihl * 4;
    const auto* tcpHeader = reinterpret_cast<const TCPHeader*>(ipData + ipHeaderLen);
    size_t tcpHeaderLen = tcpHeader->doff * 4;
    
    uint16_t srcPort = ntohs(tcpHeader->source);
    uint16_t dstPort = ntohs(tcpHeader->dest);
    uint32_t srcAddr = ipHeader->saddr;
    uint32_t dstAddr = ipHeader->daddr;
    
    // Verifica se é tráfego alvo para injeção
    if (!isTargetTraffic(dstAddr, dstPort)) {
        return;
    }
    
    // Detecta SYN para iniciar interceptação
    if (tcpHeader->syn && !tcpHeader->ack) {
        auto* conn = connManager_->findOrCreate(srcAddr, srcPort, dstAddr, dstPort);
        
        if (!conn->crypto) {
            // Inicializa túnel criptografado
            conn->crypto = std::make_unique<CryptoTunnel>();
            
            // Configura payload HTTP injector
            HttpPayloadConfig payloadConfig;
            payloadConfig.remoteHost = config_.remoteHost;
            payloadConfig.remotePort = config_.remotePort;
            payloadConfig.payloadTemplate = config_.payloadTemplate;
            payloadConfig.sniHostname = config_.sniHostname;
            payloadConfig.useProxy = config_.useProxy;
            payloadConfig.proxyHost = config_.proxyHost;
            payloadConfig.proxyPort = config_.proxyPort;
            payloadConfig.userAgent = config_.userAgent;
            
            if (!conn->crypto->connect(payloadConfig)) {
                callbacks_->logMessage("Failed to establish crypto tunnel");
                connManager_->remove(srcAddr, srcPort, dstAddr, dstPort);
                return;
            }
            
            conn->handshakeComplete = true;
            callbacks_->logMessage("New connection intercepted and tunneled");
        }
    }
    
    // Processa dados do payload se houver
    size_t dataOffset = ipHeaderLen + tcpHeaderLen;
    size_t dataLen = ipLen - dataOffset;
    
    if (dataLen > 0) {
        auto* conn = connManager_->findOrCreate(srcAddr, srcPort, dstAddr, dstPort);
        if (conn && conn->handshakeComplete && conn->crypto) {
            conn->crypto->send(ipData + dataOffset, dataLen);
            bytesSent_ += dataLen;
        }
    }
}

void VpnCore::handleUDPPacket(const uint8_t* ipData, size_t ipLen, const IPv4Header* ipHeader) {
    size_t ipHeaderLen = ipHeader->ihl * 4;
    const auto* udpHeader = reinterpret_cast<const UDPHeader*>(ipData + ipHeaderLen);
    
    uint16_t srcPort = ntohs(udpHeader->source);
    uint16_t dstPort = ntohs(udpHeader->dest);
    
    // DNS tipicamente na porta 53 - pode ser interceptado para redirecionamento
    if (dstPort == 53) {
        // Implementação de interceptação DNS se necessário
    }
}

uint16_t VpnCore::calculateChecksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *reinterpret_cast<const uint16_t*>(data);
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += *data;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

bool VpnCore::isTargetTraffic(uint32_t dstAddr, uint16_t dstPort) {
    // Filtra portas comuns de HTTP/HTTPS para interceptação
    return dstPort == 80 || dstPort == 443 || dstPort == 8080 || dstPort == 3128;
}
