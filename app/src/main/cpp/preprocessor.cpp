// ARQUIVO 4: /app/src/main/cpp/preprocessor.cpp
#include "preprocessor.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <regex>

HttpPreprocessor::HttpPreprocessor() {}

std::string HttpPreprocessor::processPayload(const std::string& templateStr,
                                              const std::string& remoteHost,
                                              int remotePort,
                                              const std::string& method,
                                              const std::string& version) {
    std::string result = templateStr;
    
    // Substituições básicas
    result = replaceAll(result, "[host]", remoteHost);
    result = replaceAll(result, "[port]", std::to_string(remotePort));
    result = replaceAll(result, "[host_port]", remoteHost + ":" + std::to_string(remotePort));
    result = replaceAll(result, "[method]", method);
    result = replaceAll(result, "[version]", version);
    result = replaceAll(result, "[protocol]", "https");
    
    // Quebras de linha
    result = replaceAll(result, "[crlf]", "\r\n");
    result = replaceAll(result, "[lf]", "\n");
    result = replaceAll(result, "[cr]", "\r");
    
    // Espaçamentos duplos para headers vazios (técnica de ofuscação)
    result = replaceAll(result, "[space]", " ");
    result = replaceAll(result, "[tab]", "\t");
    
    // User-Agent customizado
    std::string ua = "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36";
    result = replaceAll(result, "[ua]", ua);
    
    // Headers adicionais para camuflagem Vivo/TIM
    if (result.find("[keep-alive]") != std::string::npos) {
        result = replaceAll(result, "[keep-alive]", "Connection: Keep-Alive\r\n");
    }
    
    if (result.find("[accept]") != std::string::npos) {
        result = replaceAll(result, "[accept]", 
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n");
    }
    
    if (result.find("[accept-lang]") != std::string::npos) {
        result = replaceAll(result, "[accept-lang]", "Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7\r\n");
    }
    
    if (result.find("[accept-enc]") != std::string::npos) {
        result = replaceAll(result, "[accept-enc]", "Accept-Encoding: gzip, deflate, br\r\n");
    }
    
    // Técnica de fragmentação de headers (ofuscação DPI)
    if (result.find("[split]") != std::string::npos) {
        // Divide headers em múltiplos pacotes TCP
        result = replaceAll(result, "[split]", "");
    }
    
    return result;
}

std::string HttpPreprocessor::generateProxyPayload(const HttpPayloadConfig& config) {
    std::string templateStr = config.payloadTemplate;
    
    // Se template vazio, usa padrão otimizado para Vivo/TIM
    if (templateStr.empty()) {
        templateStr = "[method] [host_port] [version][crlf]"
                     "Host: [host_port][crlf]"
                     "[keep-alive]"
                     "Proxy-Connection: Keep-Alive[crlf]"
                     "[accept]"
                     "[accept-lang]"
                     "[accept-enc]"
                     "User-Agent: [ua][crlf]"
                     "[crlf]";
    }
    
    return processPayload(templateStr, config.remoteHost, config.remotePort, 
                         "CONNECT", "HTTP/1.1");
}

std::string HttpPreprocessor::generateDirectPayload(const HttpPayloadConfig& config) {
    // Para modo direto, gera um request GET/POST que parece navegação normal
    std::string templateStr = config.payloadTemplate;
    
    if (templateStr.empty()) {
        templateStr = "GET / HTTP/1.1[crlf]"
                      "Host: [host][crlf]"
                      "User-Agent: [ua][crlf]"
                      "Accept: */*[crlf]"
                      "Connection: keep-alive[crlf]"
                      "[crlf]";
    }
    
    return processPayload(templateStr, config.remoteHost, config.remotePort,
                         "GET", "HTTP/1.1");
}

bool HttpPreprocessor::validateProxyResponse(const std::string& response) {
    std::string lower = HttpUtils::toLower(response);
    
    // Aceita respostas de sucesso
    if (HttpUtils::startsWith(lower, "http/1.1 200") || 
        HttpUtils::startsWith(lower, "http/1.0 200")) {
        return true;
    }
    
    // Aceita 101 Switching Protocols (para WebSocket/UPGRADE)
    if (HttpUtils::startsWith(lower, "http/1.1 101")) {
        return true;
    }
    
    // Alguns proxies retornam 407 antes de autenticação - tratar se necessário
    if (HttpUtils::startsWith(lower, "http/1.1 407")) {
        return false; // Requer autenticação proxy
    }
    
    return false;
}

std::string HttpPreprocessor::replaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

namespace HttpUtils {
    std::vector<uint8_t> stringToBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    std::string bytesToString(const std::vector<uint8_t>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }
    
    std::string trim(const std::string& str) {
        auto start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }
    
    std::string toLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
    
    bool startsWith(const std::string& str, const std::string& prefix) {
        return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
    }
}
