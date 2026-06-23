// ARQUIVO 4: /app/src/main/cpp/preprocessor.hpp
#ifndef PREPROCESSOR_HPP
#define PREPROCESSOR_HPP

#include <string>
#include <map>
#include <vector>
#include <cstdint>

// Configuração do payload HTTP
struct HttpPayloadConfig {
    std::string remoteHost;
    int remotePort = 443;
    std::string payloadTemplate;
    std::string sniHostname;
    bool useProxy = false;
    std::string proxyHost;
    int proxyPort = 8080;
    std::string userAgent;
};

// Classe responsável pelo processamento e injeção de payloads HTTP
class HttpPreprocessor {
public:
    HttpPreprocessor();
    
    // Processa o template substituindo placeholders
    std::string processPayload(const std::string& templateStr, 
                              const std::string& remoteHost, 
                              int remotePort,
                              const std::string& method = "CONNECT",
                              const std::string& version = "HTTP/1.1");
    
    // Gera payload específico para modo proxy HTTP
    std::string generateProxyPayload(const HttpPayloadConfig& config);
    
    // Gera payload para modo direto (SNI spoofing)
    std::string generateDirectPayload(const HttpPayloadConfig& config);
    
    // Valida resposta do servidor proxy
    bool validateProxyResponse(const std::string& response);
    
private:
    std::map<std::string, std::string> placeholderMap_;
    
    void initializePlaceholders(const std::string& host, int port, 
                               const std::string& method,
                               const std::string& version,
                               const std::string& userAgent);
    std::string replaceAll(std::string str, const std::string& from, const std::string& to);
};

// Utilidades de parsing HTTP
namespace HttpUtils {
    std::vector<uint8_t> stringToBytes(const std::string& str);
    std::string bytesToString(const std::vector<uint8_t>& bytes);
    std::string trim(const std::string& str);
    std::string toLower(const std::string& str);
    bool startsWith(const std::string& str, const std::string& prefix);
}

#endif // PREPROCESSOR_HPP
