cmake_minimum_required(VERSION 3.25)
project(SecurityAssessment LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_UNITY_BUILD OFF)

if(MSVC)
  add_compile_options(
    /W4 /permissive- /utf-8 /Zc:__cplusplus
    /GS /guard:cf /DYNAMICBASE /NXCOMPAT
    /wd4100  # unreferenced formal parameter (informational noise)
  )
  add_link_options(/DYNAMICBASE /NXCOMPAT /GUARD:CF)
  add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX
                  -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00)
endif()

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/*.cpp")

add_executable(SecurityAssessment WIN32 OFF ${SOURCES})
target_include_directories(SecurityAssessment PRIVATE src)

target_link_libraries(SecurityAssessment PRIVATE
  advapi32 bcrypt iphlpapi ws2_32 ole32 oleaut32 wbemuuid
  setupapi cfgmgr32 powrprof version shlwapi crypt32)