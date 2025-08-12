# Specify the minimum required CMake version
cmake_minimum_required(VERSION 3.10)

# Define the project name
project(traffic_sniffer)

include_directories(inc)

# Add an executable target
add_executable(traffic_sniffer main.c src/checkers.c src/printers.c src/parsers)