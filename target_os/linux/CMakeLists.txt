add_executable (ytubedpi_lin "ytubedpi_lin.c" "ytubedpi_lin.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ytubedpi_lin PROPERTY C_STANDARD 17)
endif()

target_link_libraries(ytubedpi_lin
  PUBLIC -lnetfilter_queue
)
