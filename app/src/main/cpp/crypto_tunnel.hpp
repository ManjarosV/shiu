// ARQUIVO 5: /app/src/main/cpp/crypto_tunnel.hpp
#ifndef CRYPTO_TUNNEL_HPP
#define CRYPTO_TUNNEL_HPP

#include "preprocessor.hpp"
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <memory>
#include <vector>
#include <string>

// Wrapper RAII para contextos mbedTLS
class MbedtlsContext {
public:
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_net_context server_fd;
    
    MbedtlsContext();
    ~MbedtlsContext();
    
    void reset();
};

// Túnel criptografado usando mbedTLS com SNI customizável
class CryptoTunnel {
public:
    CryptoTunnel();
    ~CryptoTunnel();
    
    // Estabelece conexão com o servidor remoto via proxy ou direto
    bool connect(const HttpPayloadConfig& config);
    
    // Envia dados através do túnel criptografado
    ssize_t send(const uint8_t* data, size_t len);
    
    // Recebe dados do túnel
    ssize_t receive(uint8_t* buffer, size_t len);
    
    // Verifica se o túnel está ativo
    bool isConnected() const;
    
    // Fecha a conexão
    void close();
    
private:
    std::unique_ptr<MbedtlsContext> ctx_;
    bool connected_ = false;
    HttpPayloadConfig currentConfig_;
    
    // Conexão de socket de baixo nível
    int sockFd_ = -1;
    
    bool establishSocketConnection();
    bool performHttpProxyHandshake();
    bool setupMbedtls();
    bool performSslHandshake();
    
    // SNI personalizado para ofuscação
    void configureSni(const std::string& hostname);
};

#endif // CRYPTO_TUNNEL_HPP
