cmake_minimum_required(VERSION 3.20)
project(p15 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL 3.5 REQUIRED)
message(STATUS "P15: OpenSSL ${OPENSSL_VERSION} (${OPENSSL_CRYPTO_LIBRARY})")

add_executable(p15_smoke src/smoke.c)
target_link_libraries(p15_smoke PRIVATE OpenSSL::Crypto)
target_compile_options(p15_smoke PRIVATE -Wall -Wextra)

add_executable(p15_a1 src/p15_a1.c)
target_link_libraries(p15_a1 PRIVATE OpenSSL::Crypto)
target_compile_options(p15_a1 PRIVATE -Wall -Wextra -O2)

# Exploratory validation of the cost model (D-026): A1, A1b, A2, A3 on the native platform.
# Reuses p15_a1.c unchanged (included with its main() renamed).
add_executable(p15_arch src/p15_arch.c)
target_link_libraries(p15_arch PRIVATE OpenSSL::Crypto m)
target_compile_options(p15_arch PRIVATE -Wall -Wextra -O2)
