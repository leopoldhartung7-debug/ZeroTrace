cmake_minimum_required(VERSION 3.20)
project(OceanFiveMScanner CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build with vcpkg toolchain:
#   cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
find_package(imgui CONFIG REQUIRED)

add_executable(OceanScanner WIN32
    src/main.cpp
    src/scanner.cpp
    src/report.cpp
)

target_link_libraries(OceanScanner PRIVATE
    imgui::imgui
    d3d11
    dxgi
    dwmapi
    bcrypt
    winhttp
    wintrust
    version
    shell32
)

target_compile_definitions(OceanScanner PRIVATE
    UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
)

if (MSVC)
    target_compile_options(OceanScanner PRIVATE /W4 /permissive-)
    set_property(TARGET OceanScanner PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()
