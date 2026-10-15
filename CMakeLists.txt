cmake_minimum_required(VERSION 3.25)
project(SecurityAssessment LANGUAGES CXX)

# --- Language standard (vcxproj: LanguageStandard=stdcpp23, ConformanceMode=true) ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_UNITY_BUILD OFF)

# The vcxproj uses the default (dynamic) CRT: /MD in Release, /MDd in Debug.
# CMake's default MSVC runtime is the same, so no CMAKE_MSVC_RUNTIME_LIBRARY override.

if(NOT MSVC)
  message(FATAL_ERROR "SecurityAssessment is a Windows/MSVC-only project.")
endif()

# Toolset note: the vcxproj uses v143 for Debug and v145 for Release. CMake cannot
# select a toolset per configuration, so pick one at configure time, e.g.:
#   cmake -S . -B build -G "Visual Studio 18 2026" -A x64 -T v145

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/*.cpp")

# Console subsystem (vcxproj: SubSystem=Console) -> no WIN32 keyword.
add_executable(SecurityAssessment ${SOURCES})
target_include_directories(SecurityAssessment PRIVATE src)

# --- Compiler settings (vcxproj ClCompile) ---
target_compile_definitions(SecurityAssessment PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
  WINVER=0x0A00 _WIN32_WINNT=0x0A00)

target_compile_options(SecurityAssessment PRIVATE
  /W4            # WarningLevel=Level4
  /permissive-   # ConformanceMode / AdditionalOptions
  /utf-8         # AdditionalOptions
  /MP            # MultiProcessorCompilation
  /sdl           # SDLCheck
  /guard:cf      # ControlFlowGuard=Guard
)

# --- Linker settings (vcxproj Link) ---
target_link_options(SecurityAssessment PRIVATE
  /SUBSYSTEM:CONSOLE
  /GUARD:CF
  /DEBUG         # GenerateDebugInformation=true
  /DYNAMICBASE /NXCOMPAT   # VS defaults, kept explicit
)

# Debug info: ProgramDatabase (/Zi) in all configs, like the vcxproj.
# Release: WholeProgramOptimization=true (/GL + /LTCG).
set_target_properties(SecurityAssessment PROPERTIES
  MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,Release>:ProgramDatabase>"
  INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
)

# Libraries (the sources also pull some in via #pragma comment).
target_link_libraries(SecurityAssessment PRIVATE
  advapi32 bcrypt iphlpapi ws2_32 ole32 oleaut32 wbemuuid
  setupapi cfgmgr32 powrprof version shlwapi crypt32 wscapi shell32 wuguid tbs netapi32)

option(SA_BUILD_TESTS "Build native regression checks" OFF)
if(SA_BUILD_TESTS)
  enable_testing()
  set(TEST_SOURCES ${SOURCES})
  list(FILTER TEST_SOURCES EXCLUDE REGEX "/main\\.cpp$")
  add_executable(SecurityAssessmentTests tests/RegressionTests.cpp ${TEST_SOURCES})
  foreach(prop INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_OPTIONS LINK_LIBRARIES)
    get_target_property(value SecurityAssessment ${prop})
    set_property(TARGET SecurityAssessmentTests PROPERTY ${prop} "${value}")
  endforeach()
  add_test(NAME native_regressions COMMAND SecurityAssessmentTests)
endif()
