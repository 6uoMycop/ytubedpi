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


if (MSVC)
	add_subdirectory ("target_os/windows")
endif (MSVC)

if (UNIX)
	add_subdirectory ("target_os/linux")
endif(UNIX)
