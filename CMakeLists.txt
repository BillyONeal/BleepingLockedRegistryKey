cmake_minimum_required(VERSION 3.2.1)
set(CMAKE_USER_MAKE_RULES_OVERRIDE
    ${CMAKE_CURRENT_SOURCE_DIR}/c_flag_overrides.cmake)
set(CMAKE_USER_MAKE_RULES_OVERRIDE_CXX
    ${CMAKE_CURRENT_SOURCE_DIR}/cxx_flag_overrides.cmake)
project (BleepingLockedRegistryKey)

add_definitions(-D_SCL_SECURE_NO_WARNINGS)
add_definitions(-DUNICODE)
add_definitions(-D_UNICODE)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
add_definitions(-DNOMINMAX)
add_definitions(-DNTDDI_VERSION=0x05010200)
add_definitions(-D_WIN32_WINNT=0x0501)
add_definitions(-DBUILD_WINDOWS)

add_compile_options(/MP /GR- /W4 /EHsc)
add_executable(BleepingLockedRegistryKey main.c)
set_target_properties(BleepingLockedRegistryKey PROPERTIES LINK_FLAGS "\"/level='requireAdministrator'\" /SUBSYSTEM:CONSOLE")
