cmake_minimum_required(VERSION 3.23)
project("bpf-verifier")

include("cmake/options.cmake")
include("cmake/settings.cmake")

add_subdirectory("linux")
add_subdirectory("libbpf")

set(src_root "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_command(
  OUTPUT src_root/bin/"${TARGET}"
  COMMAND make "${TARGET}"
  WORKING_DIRECTORY ${src_root}
)

add_custom_command(
  OUTPUT "${src_root}/bin/local-${TARGET}"
  COMMAND make "local-${TARGET}"
  WORKING_DIRECTORY ${src_root}
)

# TODO: add other deps
add_custom_target("run"
  DEPENDS "kernel"
  DEPENDS "libbpf"
  DEPENDS  src_root/bin/"${TARGET}"
)

add_custom_target("local"
  DEPENDS "reglibbpf"
  DEPENDS  "${src_root}/bin/local-${TARGET}"
)


add_custom_target("my_clean"
  COMMAND make clean
  WORKING_DIRECTORY ${src_root}
  COMMAND "${CMAKE_COMMAND}" --build build --target kernel_clean
  COMMAND "${CMAKE_COMMAND}" --build build --target libbpf_clean
)

add_custom_target("clean_apps"
  COMMAND make clean
  WORKING_DIRECTORY ${src_root}
)
