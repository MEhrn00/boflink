cmake_minimum_required(VERSION 3.29)
project(boflink-example-hello-world LANGUAGES C)

include(cmake/SetupBoflink.cmake)

add_executable(hello-world
  src/go.c
  src/hello.c
)

set_target_properties(hello-world PROPERTIES
  SUFFIX .bof
  LINKER_TYPE boflink
)
