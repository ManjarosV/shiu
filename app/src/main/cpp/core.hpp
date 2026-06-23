// ARQUIVO 3: /app/src/main/cpp/core.hpp
#ifndef CORE_HPP
#define CORE_HPP

#include <cstdint>
#include <string>
#include <memory>
#include <atomic>
#include <vector>
#include <array>
#include <functional>

// Estrutura de configuração do túnel
struct TunnelConfig {
    int tunFd = -1;
    std::string remoteHost;
    int remotePort = 443;
    std::string payloadTemplate;
    std::string sniHostname;
    bool useProxy = false;
    std::string proxyHost;
    int proxyPort = 8080;
    std::string userAgent;
};

// Interface de callbacks para comunicação com Java
class CoreCallbacks {
public:
    virtual ~CoreCallbacks() = default;
    virtual void updateStats(uint64_t sent, uint64_t received) = 0;
    virtual void logMessage(const std::string& msg) = 0;
    virtual void reportError(const std::string& error) = 0;
};

// Estruturas de pacote IP
#pragma pack(push, 1)
struct IPv4Header {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct IPv6Header {
    uint32_t version:4;
    uint32_t traffic_class:8;
    uint32_t flow_label:20;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t saddr[16];
    uint8_t daddr[16];
};

struct TCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct UDPHeader {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};
#pragma pack(pop)

// Classe principal do core VPN
class VpnCore {
public:
    VpnCore(std::unique_ptr<CoreCallbacks> callbacks, const TunnelConfig& config);
    ~VpnCore();
    
    void run();
    void stop();
    
private:
    std::unique_ptr<CoreCallbacks> callbacks_;
    TunnelConfig config_;
    std::atomic<bool> running_{false};
    int epollFd_ = -1;
    
    // Estatísticas
    std::atomic<uint64_t> bytesSent_{0};
    std::atomic<uint64_t> bytesReceived_{0};
    
    // Buffer de I/O
    static constexpr size_t BUFFER_SIZE = 65536;
    std::vector<uint8_t> buffer_;
    
    // Métodos internos
    void processTunPacket();
    void handleIPv4Packet(const uint8_t* data, size_t len);
    void handleIPv6Packet(const uint8_t* data, size_t len);
    void handleTCPPacket(const uint8_t* ipData, size_t ipLen, const IPv4Header* ipHeader);
    void handleUDPPacket(const uint8_t* ipData, size_t ipLen, const IPv4Header* ipHeader);
    
    uint16_t calculateChecksum(const uint8_t* data, size_t len);
    bool isTargetTraffic(uint32_t dstAddr, uint16_t dstPort);
    
    // Conexões gerenciadas
    class ConnectionManager;
    std::unique_ptr<ConnectionManager> connManager_;
};

#endif // CORE_HPP
