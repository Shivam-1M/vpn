cmake_minimum_required(VERSION 3.16)
project(VpnRecoveryTool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the required Qt components
find_package(Qt6 COMPONENTS Core REQUIRED)

# Add the executable target
add_executable(VpnRecoveryTool main.cpp)

# Link against the Qt Core library
target_link_libraries(VpnRecoveryTool PRIVATE Qt6::Core)

# Define install location (optional but good practice)
install(TARGETS VpnRecoveryTool
    DESTINATION bin
)