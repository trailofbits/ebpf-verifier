# Submodule manager
find_package(Git REQUIRED)

add_custom_target("libbpf_submodule_initializer" DEPENDS
  COMMENT "bpfverifier: Initializing the libbpf submodule"
  COMMAND pwd
  COMMAND "${GIT_EXECUTABLE}" submodule update --init "src"

  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
  VERBATIM
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/build/libbpf.a"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/src"
  COMMAND make -f ../../Makefile_special
  VERBATIM
)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/build_reg/libbpf.a"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/src"
  COMMAND make clean
  COMMAND BUILD_STATIC_ONLY=y OBJDIR=../../build_reg DESTDIR=../../root_reg make install
  VERBATIM
)

# target to make libbpf.a with mods
add_custom_target("libbpf" DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/build/libbpf.a"
)

# target to make libbpf.a without mods
add_custom_target("reglibbpf" DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/build_reg/libbpf.a"
)

add_custom_target("libbpf_clean"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMAND rm -rf build
  COMMAND rm -rf root
  COMMAND rm -rf build_reg
  COMMAND rm -rf root_reg
)
