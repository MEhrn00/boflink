include_guard()

find_program(BOFLINK boflink REQUIRED
  HINTS ${CMAKE_SOURCE_DIR}/../../target/debug
)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  configure_file(${CMAKE_CURRENT_LIST_DIR}/boflink.specs.in
    ${CMAKE_BINARY_DIR}/boflink/boflink.specs @ONLY)
  set(CMAKE_C_USING_LINKER_boflink "-specs=${CMAKE_BINARY_DIR}/boflink/boflink.specs")
elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang"
    AND CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "GNU")
  set(CMAKE_C_USING_LINKER_boflink "--ld-path=${BOFLINK} -nostartfiles")
else()
  set(CMAKE_C_USING_LINKER_boflink "${BOFLINK}")
endif()
