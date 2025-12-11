# Specify the minimum version of CMake required.
cmake_minimum_required(VERSION 3.16)

# Define the project name.
project(VpnDesktopClient VERSION 1.0)

# Set the C++ standard to C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Automatically run MOC, UIC, and RCC when needed.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Find the required Qt6 packages. We need Core, GUI, and Widgets for a desktop app.
find_package(Qt6 COMPONENTS Core Gui Widgets Network REQUIRED)

# Find the PNG library, which QtGui depends on.
find_package(PNG REQUIRED)

# --- Link the Rust Core Library ---
# Define the path to the directory containing our compiled Rust .so/.dll/.dylib file.
# IMPORTANT: Adjust this path if your projects are in a different structure.
set(RUST_LIB_PATH ${CMAKE_SOURCE_DIR}/../vpn_client_core/target/debug)

# Find the compiled Rust library.
# The name on Linux is libvpn_client_core.so, on Windows vpn_client_core.dll,
# and on macOS libvpn_client_core.dylib.
find_library(VPN_CORE_LIB
  NAMES vpn_client_core
  HINTS ${RUST_LIB_PATH}
  REQUIRED
)

# Add the directory containing the Rust library to the linker path.
link_directories(${RUST_LIB_PATH})

# Define the executable target for our application.
add_executable(VpnDesktopClient
  src/main.cpp
  src/mainwindow.cpp
  src/mainwindow.h
  src/mainwindow.ui
  src/vpn_client_core.h
  src/cryptomanager.cpp
  src/cryptomanager.h
  src/signupdialog.cpp
  src/signupdialog.h
)

# Add the recovery tool subdirectory to the build process
add_subdirectory(recovery_tool)

# Link the Qt6 libraries to our executable.
target_link_libraries(VpnDesktopClient
  PRIVATE
  Qt6::Core
  Qt6::Gui
  Qt6::Widgets
  Qt6::Network
  ${PNG_LIBRARIES}
  ${VPN_CORE_LIB}  # Link our Rust core library
)