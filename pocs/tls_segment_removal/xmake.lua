add_requires("openssl3")
add_packages("openssl3")

target("segment_traffic_gen")
    set_kind("binary")
    add_files("traffic_gen.cc")
    add_links("ws2_32")
