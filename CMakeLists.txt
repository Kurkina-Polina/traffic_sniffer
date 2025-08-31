# Specify the minimum required CMake version
cmake_minimum_required(VERSION 3.10)

# Define the project name
project(traffic_sniffer)

include_directories(inc)

# Add an executable target
add_executable(traffic_sniffer main.c src/checkers.c src/printers.c src/parsers_str.c src/dissecters.c src/get_help.c src/handles_sockets.c src/handles_user_input.c)
target_compile_options(traffic_sniffer PRIVATE "-g;-Wall;-Wextra;-O3")