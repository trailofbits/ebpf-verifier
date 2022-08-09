file(STRINGS "${VERSION_FILE}" git_submodule_tag)

if(NOT "${git_submodule_tag}" STREQUAL "${EXPECTED_VERSION}")
  message(FATAL_ERROR "The git submodule is at version ${git_submodule_tag}. Expected: ${EXPECTED_VERSION}")
endif()
