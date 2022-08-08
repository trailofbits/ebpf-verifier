# Submodule manager
find_package(Git REQUIRED)

set(libbpf_root_makefile "${CMAKE_CURRENT_SOURCE_DIR}/src/src/Makefile")

# add_custom_command(
#   COMMENT "bpfverifier: Updating the libbpf submodule"

#   COMMAND "${GIT_EXECUTABLE}" fetch --tags
#   COMMAND "${GIT_EXECUTABLE}" checkout -f "${BPFVERIFIER_LINUX_VERSION}"
#   COMMAND "${GIT_EXECUTABLE}" describe --tags > "${linux_version_file}.temp"
#   COMMAND "${CMAKE_COMMAND}" "-DEXPECTED_VERSION:STRING=${BPFVERIFIER_LINUX_VERSION}" "-DVERSION_FILE:PATH=${linux_version_file}.temp" -P "${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_version.cmake"
#   COMMAND "${CMAKE_COMMAND}" -E rename "${linux_version_file}.temp" "${linux_version_file}"

#   DEPENDS "linux_submodule_initializer"
#   WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
#   VERBATIM

# )

# add_custom_target("linux_submodule_updater" DEPENDS
#   "${linux_version_file}"
# )

add_custom_command(
  OUTPUT "${libbpf_root_makefile}"
  COMMENT "bpfverifier: Initializing the libbpf submodule"

  COMMAND "${GIT_EXECUTABLE}" submodule update --init "src"

  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  VERBATIM
)

add_custom_target("libbpf_submodule_initializer" DEPENDS
  "${libbpf_root_makefile}"
)
