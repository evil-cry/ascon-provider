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

add_subdirectory(libprov)
add_subdirectory(LibAscon)

include(libprov/cmake/provider.cmake)
setup_provider_openssl()

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/akif_ascon_params.c
                          ${CMAKE_CURRENT_BINARY_DIR}/akif_ascon_params.h
                   COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/libprov/perl/gen_param_LL.pl
                          ${CMAKE_CURRENT_BINARY_DIR}/akif_ascon_params.c
                          ${CMAKE_CURRENT_BINARY_DIR}/akif_ascon_params.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/akif_ascon_params.dat
                   MAIN_DEPENDENCY akif_ascon_params.dat
                   DEPENDS libprov/perl/gen_param_LL.pl)

set(akif_ascon_source 
    akif_ascon.c
    akif_ascon_common.c
    akif_ascon_aead128.c
    akif_ascon_aead128a.c
    akif_ascon_aead80pq.c
    akif_ascon_digest_hash.c
    akif_ascon_digest_xof.c
    ${CMAKE_CURRENT_BINARY_DIR}/akif_ascon_params.c
)
# Build provider with unique target name but output file as "ascon"
# (LibAscon already has a target named "ascon", so we use "ascon_provider" for the target)
build_provider(ascon_provider "${akif_ascon_source}" libprov)
# Override output name to "ascon" to match OpenSSL provider naming conventions
set_target_properties(ascon_provider PROPERTIES OUTPUT_NAME "ascon")
target_link_libraries(ascon_provider PRIVATE ascon128)
target_include_directories(ascon_provider PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/)

# Testing
get_property(_is_multiconfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if (_is_multiconfig)
  set(ASCON_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>")
else()
  set(ASCON_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
unset(_is_multiconfig)
message(STATUS "Determined the build time Ascon provider location to be '${ASCON_MODULE_DIRECTORY}'")

set(TEST_ENVIRONMENT
  "OPENSSL_MODULES=${ASCON_MODULE_DIRECTORY}"
  "OPENSSL_PROGRAM=${OPENSSL_PROGRAM}"
  "OPENSSL_RUNTIME_DIR=${OPENSSL_RUNTIME_DIR}"
  "OPENSSL_LIBRARY_DIR=$<IF:$<BOOL:${WIN32}>,${OPENSSL_RUNTIME_DIR},${OPENSSL_LIBRARY_DIR}>"
  "SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}"
  "PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t"
  )

add_library(test_common STATIC test_common.c)
target_include_directories(test_common PUBLIC ${OPENSSL_INCLUDE_DIR})

add_executable(test_akif_ascon test_akif_ascon.c)
target_link_libraries(test_akif_ascon
  PRIVATE test_common OpenSSL::Crypto)
add_test(NAME akif_ascon COMMAND test_akif_ascon)
set_tests_properties(akif_ascon PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

option(EXTRA_TESTS "Enable extra (failing) tests" OFF)
option(EXTRA_TAP_TESTS "Enable extra (failing) tests using TAP" ${EXTRA_TESTS})

if(EXTRA_TESTS)
    add_executable(test_akif_ascon_err
      test_akif_ascon_err.c)
    if (MSVC)
      target_link_libraries(test_akif_ascon_err
        PRIVATE test_common OpenSSL::Crypto OpenSSL::applink)
    else ()
      target_link_libraries(test_akif_ascon_err
        PRIVATE test_common OpenSSL::Crypto)
    endif ()
    add_test(NAME akif_ascon_err COMMAND test_akif_ascon_err)
    set_tests_properties(akif_ascon_err PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

    if (WIN32)
      if (DEFINED OPENSSL_LIBCRYPTO_SHARED)
        cmake_path(GET OPENSSL_LIBCRYPTO_SHARED STEM OPENSSL_LIBCRYPTO_SHARED_NAME)
        add_custom_command(
          TARGET test_akif_ascon POST_BUILD
          COMMAND cmake -E copy
            "${OPENSSL_LIBCRYPTO_SHARED}"
            "${ASCON_MODULE_DIRECTORY}/${OPENSSL_LIBCRYPTO_SHARED_NAME}.dll")
        add_custom_command(
          TARGET test_akif_ascon_err POST_BUILD
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
          COMMAND ${PROVE} -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/t)
        set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
    endif(EXTRA_TAP_TESTS)
endif(EXTRA_TESTS)

# No installation instruction, as this should never be used in production
# If you still want to do so, just copy ascon.so / ascon.dll to an
# appropriate location.
