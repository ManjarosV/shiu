# ARQUIVO 6: /app/src/main/cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.18.1)

project("netcore")

# Configuração do C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Flags de compilação otimizadas para Android/ARM
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fPIC -fexceptions -frtti")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror=return-type")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Flags específicas por arquitetura
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=softfp -mfpu=neon")
elseif(ANDROID_ABI STREQUAL "arm64-v8a")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a+crypto")
endif()

# Diretórios de include
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include
)

# mbedTLS (assumindo que está no mesmo diretório ou via FetchContent)
# Se mbedTLS estiver em subdiretório, descomente:
# add_subdirectory(mbedtls)

# Se usar mbedTLS pré-compilado do NDK ou externo, ajuste os paths:
set(MBEDTLS_LIBRARIES 
    mbedtls
    mbedx509
    mbedtls
)

# Fontes do projeto
set(NETCORE_SOURCES
    jni_bridge.cpp
    core.cpp
    preprocessor.cpp
    crypto_tunnel.cpp
)

# Cria biblioteca compartilhada
add_library(netcore SHARED ${NETCORE_SOURCES})

# Encontra bibliotecas do NDK
find_library(log-lib log)
find_library(android-lib android)

# Linkagem
target_link_libraries(netcore
    ${MBEDTLS_LIBRARIES}
    ${log-lib}
    ${android-lib}
    z  # compressão
)

# Opções de visibilidade de símbolos (segurança)
set_target_properties(netcore PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

# Se precisar linkar mbedTLS estático, adicione:
# target_link_libraries(netcore 
#     ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libmbedtls.a
#     ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libmbedx509.a
#     ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libmbedcrypto.a
# )
