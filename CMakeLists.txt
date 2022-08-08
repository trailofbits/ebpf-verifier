cmake_minimum_required(VERSION 3.23)
project("bpf-verifier")

include("cmake/options.cmake")
include("cmake/settings.cmake")

add_subdirectory("linux")
add_subdirectory("libbpf")

add_custom_command(
  OUTPUT "${TARGET}"
  COMMAND make "${TARGET}"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# TODO: add other deps
add_custom_target("run"
  DEPENDS  "${TARGET}"
)
