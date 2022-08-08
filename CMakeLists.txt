cmake_minimum_required(VERSION 3.23)
project("bpf-verifier")

include("cmake/options.cmake")
include("cmake/settings.cmake")

add_subdirectory("linux")
add_subdirectory("libbpf")
