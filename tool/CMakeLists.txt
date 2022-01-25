add_executable(
  bssl

  args.cc
  ciphers.cc
  client.cc
  const.cc
  digest.cc
  fd.cc
  file.cc
  generate_ech.cc
  generate_ed25519.cc
  genrsa.cc
  pkcs12.cc
  rand.cc
  server.cc
  sign.cc
  speed.cc
  tool.cc
  transport_common.cc
)
if (BORINGSSL_BUILD_TESTS)
install_if_enabled(TARGETS bssl DESTINATION ${INSTALL_DESTINATION_DEFAULT})
endif()
target_link_libraries(bssl ssl crypto)
