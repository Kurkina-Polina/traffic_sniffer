# Network Packet Filter (TCP Server)

## Server Setup
1. Build the project using CMake:
   ```bash
   cmake CMakeLists.txt
   make

2. Run the server by specifying IP address and port:
    ```bash
    ./server -a <IP> -p <PORT>
3. Example to work on 127.0.0.1 on port 8080:
    ```bash
    ./server -a 127.0.0.1 -p 8080

## Client Connection
Users can connect to the server via telnet:
    ```bash
    telnet <IP> <PORT>
After connection, filter management commands become available.

## Available Commands
add <key> <value> [<key> <value> ...] - Add filter
(Example: add src_ipv4 192.168.1.1 dst_tcp 80)

print - Show filter statistics

exit - Close connection

del <filter_number> - Delete filter (not supported yet)

Supported Filter Keys

src_mac - source MAC

dst_mac - destination MAC

vlan_id - Vlan id 

interface - Name of interface

ether_type - Ethernet frame type

src_ipv4 - source IPv4

dst_ipv4 - destination IPv4

ip_protocol - IP protocol

src_tcp/dst_tcp - TCP port

src_udp/dst_udp - UDP port

## Current Limitations

Maximum of 10 active filters

Only one value per key in filter (duplicates are ignored)

Deletion (del) not yet implemented

filters on IPv6, vlan_id, interface not supported

