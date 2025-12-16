# CMakeList.txt: проект CMake для ytubedpi; включите исходный код и определения,
# укажите здесь логику для конкретного проекта.
#
cmake_minimum_required (VERSION 3.8)

# Включение горячей перезагрузки для компиляторов MSVC, если поддерживается.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

include_directories(
	"deps/WinDivert/include"
)
link_directories("deps/WinDivert/x64")

project ("ytubedpi")

# Добавьте источник в исполняемый файл этого проекта.
add_executable (ytubedpi "ytubedpi.c" "ytubedpi.h")

# Copy DLL and SYS to be near EXE
file(COPY "${CMAKE_HOME_DIRECTORY}/deps/WinDivert/x64/WinDivert.dll" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY "${CMAKE_HOME_DIRECTORY}/deps/WinDivert/x64/WinDivert64.sys" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# Copy scripts to be near EXE
file(GLOB G_VAR_CONFIGS "${CMAKE_HOME_DIRECTORY}/misc/scripts_win/*") # For wildcard COPY
file(COPY ${G_VAR_CONFIGS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ytubedpi PROPERTY C_STANDARD 17)
endif()

target_link_libraries(ytubedpi
	PUBLIC WinDivert
	PUBLIC wsock32
	PUBLIC Ws2_32
)

# TODO: Добавьте тесты и целевые объекты, если это необходимо.
