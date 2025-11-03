cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(
  akif-ascon-provider
  VERSION 0.1
  DESCRIPTION "A very small demonstration that shows the minimum required things for a cipher in an OpenSSL 3.0 module, including provider specific error reasons."
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)
# I use my github handle here
add_compile_definitions(AUTHOR="@theakifmehmood")

enable_testing()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

add_subdirectory(LibAscon)

# Provider source files - using new OpenSSL directory structure
set(ascon_provider_source
    providers/implementations/ciphers/cipher_ascon.c
    providers/implementations/ciphers/ciphercommon_ascon.c
    providers/implementations/ciphers/cipher_ascon128.c
    # Future implementations:
    # providers/implementations/ciphers/cipher_ascon128a.c
    # providers/implementations/ciphers/cipher_ascon80pq.c
)

# Build provider as shared library
add_library(ascon_provider SHARED ${ascon_provider_source})

# Set provider output name without lib prefix (OpenSSL convention)
set_target_properties(ascon_provider PROPERTIES
    OUTPUT_NAME "ascon"
    PREFIX ""
)

# Link against LibAscon
target_link_libraries(ascon_provider PRIVATE ascon128)

# Include directories
target_include_directories(ascon_provider PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/LibAscon/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/providers/implementations/ciphers
)

# Set C standard
set_target_properties(ascon_provider PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)

# Add compile definitions
target_compile_definitions(ascon_provider PRIVATE AUTHOR="@theakifmehmood")

# Testing
get_property(_is_multiconfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if (_is_multiconfig)
  set(ASCON_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>")
else()
  set(ASCON_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
unset(_is_multiconfig)
message(STATUS "Determined the build time Ascon provider location to be '${ASCON_MODULE_DIRECTORY}'")

# Set OpenSSL environment variables (can be overridden)
if(NOT DEFINED OPENSSL_PROGRAM)
  set(OPENSSL_PROGRAM "")
endif()
if(NOT DEFINED OPENSSL_RUNTIME_DIR)
  set(OPENSSL_RUNTIME_DIR "")
endif()
if(NOT DEFINED OPENSSL_LIBRARY_DIR)
  set(OPENSSL_LIBRARY_DIR "")
endif()

set(TEST_ENVIRONMENT
  "OPENSSL_MODULES=${ASCON_MODULE_DIRECTORY}"
  "OPENSSL_PROGRAM=${OPENSSL_PROGRAM}"
  "OPENSSL_RUNTIME_DIR=${OPENSSL_RUNTIME_DIR}"
  "OPENSSL_LIBRARY_DIR=$<IF:$<BOOL:${WIN32}>,${OPENSSL_RUNTIME_DIR},${OPENSSL_LIBRARY_DIR}>"
  "SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}"
  "PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/tests/recipes"
  )

add_library(test_common STATIC tests/test_common.c)
target_link_libraries(test_common PUBLIC OpenSSL::Crypto)
target_include_directories(test_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_executable(test_ascon tests/test_ascon.c)
target_include_directories(test_ascon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(test_ascon
  PRIVATE test_common OpenSSL::Crypto)
add_test(NAME ascon COMMAND test_ascon)
set_tests_properties(ascon PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

option(EXTRA_TESTS "Enable extra (failing) tests" OFF)
option(EXTRA_TAP_TESTS "Enable extra (failing) tests using TAP" ${EXTRA_TESTS})

if(EXTRA_TESTS)
    add_executable(test_ascon_err
      tests/test_ascon_err.c)
    target_include_directories(test_ascon_err PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    if (MSVC)
      target_link_libraries(test_ascon_err
        PRIVATE test_common OpenSSL::Crypto OpenSSL::applink)
    else ()
      target_link_libraries(test_ascon_err
        PRIVATE test_common OpenSSL::Crypto)
    endif ()
    add_test(NAME ascon_err COMMAND test_ascon_err)
    set_tests_properties(ascon_err PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

    if (WIN32)
      if (DEFINED OPENSSL_LIBCRYPTO_SHARED)
        cmake_path(GET OPENSSL_LIBCRYPTO_SHARED STEM OPENSSL_LIBCRYPTO_SHARED_NAME)
        add_custom_command(
          TARGET test_ascon POST_BUILD
          COMMAND cmake -E copy
            "${OPENSSL_LIBCRYPTO_SHARED}"
            "${ASCON_MODULE_DIRECTORY}/${OPENSSL_LIBCRYPTO_SHARED_NAME}.dll")
        add_custom_command(
          TARGET test_ascon_err POST_BUILD
          COMMAND cmake -E copy
            "${OPENSSL_LIBCRYPTO_SHARED}"
            "${ASCON_MODULE_DIRECTORY}/${OPENSSL_LIBCRYPTO_SHARED_NAME}.dll")
      endif()
    endif()

    if(EXTRA_TAP_TESTS)
        # Test with OpenSSL, using TAP
        if (MSVC)
          set(PROVE prove.bat)
        else()
          set(PROVE prove)
        endif()
        add_test(NAME openssl
          COMMAND ${PROVE} -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/tests/recipes)
        set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
    endif(EXTRA_TAP_TESTS)
endif(EXTRA_TESTS)

# No installation instruction, as this should never be used in production
# If you still want to do so, just copy ascon.so / ascon.dll to an
# appropriate location.
