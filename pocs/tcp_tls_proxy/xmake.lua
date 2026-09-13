target("plaintext_handshake_sim")
    set_kind("binary")
    add_files("plaintext_handshake_sim.cc")
    add_links("ws2_32")
