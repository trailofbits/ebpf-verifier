# Submodule manager
find_package(Git REQUIRED)

add_custom_target("libbpf_submodule_initializer" DEPENDS
  COMMENT "bpfverifier: Initializing the libbpf submodule"
  COMMAND pwd
  COMMAND "${GIT_EXECUTABLE}" submodule update --init "src"

  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
  VERBATIM
)
