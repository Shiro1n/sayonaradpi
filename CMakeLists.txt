cmake_minimum_required(VERSION 3.20)
project(sayonaradpi C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/lib/include)
include_directories(${CMAKE_SOURCE_DIR}/lib/Include/npcap)

# Link directories
link_directories(${CMAKE_SOURCE_DIR}/lib)
link_directories(${CMAKE_SOURCE_DIR}/lib/Include/npcap)

# Add source files
add_executable(sayonaradpi
        src/main.c
        src/packet_capture.c
        src/packet_mod.c
        src/packet_encrypt.c
        src/utils.c
)

# Link libraries
target_link_libraries(sayonaradpi
        ${CMAKE_SOURCE_DIR}/lib/libnet.a
        ${CMAKE_SOURCE_DIR}/lib/libPacket.a
        ${CMAKE_SOURCE_DIR}/lib/libwpcap.a
        ws2_32
        iphlpapi
        kernel32
        user32
        gdi32
        shell32
        ole32
        oleaut32
        uuid
        advapi32
)

# Copy required DLLs to the output directory
add_custom_command(TARGET sayonaradpi POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/lib/Include/dlls/Packet.dll
        $<TARGET_FILE_DIR:sayonaradpi>)
add_custom_command(TARGET sayonaradpi POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/lib/Include/dlls/wpcap.dll
        $<TARGET_FILE_DIR:sayonaradpi>)
