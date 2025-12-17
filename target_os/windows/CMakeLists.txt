add_executable (ytubedpi_win "ytubedpi_win.c" "ytubedpi_win.h")

# Copy DLL and SYS to be near EXE
file(COPY "${CMAKE_HOME_DIRECTORY}/deps/WinDivert/x64/WinDivert.dll" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY "${CMAKE_HOME_DIRECTORY}/deps/WinDivert/x64/WinDivert64.sys" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# Copy scripts to be near EXE
file(GLOB G_VAR_CONFIGS "${CMAKE_HOME_DIRECTORY}/misc/scripts_win/*") # For wildcard COPY
file(COPY ${G_VAR_CONFIGS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ytubedpi_win PROPERTY C_STANDARD 17)
endif()

target_link_libraries(ytubedpi_win
    PUBLIC WinDivert
    PUBLIC wsock32
    PUBLIC Ws2_32
)
