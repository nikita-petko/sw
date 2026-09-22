add_requires("openssl3")
add_packages("openssl3")

target("plaintext_handshake_sim")
    set_kind("binary")
    add_files("plaintext_handshake_sim.cc")
    add_links("ws2_32")

target("keystore_mock")
    set_kind("binary")
    add_files("keystore_mock.cc")
    add_links("ws2_32")
