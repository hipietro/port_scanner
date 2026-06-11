Important note

This is a TCP connect scanner, not a raw SYN scanner.

A raw SYN scanner manually crafts TCP packets and usually requires raw sockets and root privileges.

This project instead uses the operating system TCP stack through the standard connect() system call. This makes it simpler, safer, and better suited for learning socket programming in C++.

Features
Hostname or IPv4 input
Custom TCP port range
Multi-threaded scanning using std::thread
Dynamic work distribution using std::atomic
Thread-safe result collection using std::mutex
Non-blocking sockets
Timeout handling with select()
Clean output showing only open ports
macOS/POSIX socket implementation
Requirements

This first version targets macOS.

You need a C++17-compatible compiler. On macOS, clang++ is usually already available if Xcode Command Line Tools are installed.

Check your compiler with:

clang++ --version

If the command is not available, install Xcode Command Line Tools:

xcode-select --install
Build

From the project root directory:

clang++ -std=c++17 src/main.cpp -o portscanner -pthread

You can also use:

g++ -std=c++17 src/main.cpp -o portscanner -pthread

On macOS, g++ is often an alias to Apple Clang.

Usage
./portscanner <host> <start_port> <end_port> <threads>

Example:

./portscanner 127.0.0.1 1 1024 50

Example:

./portscanner scanme.nmap.org 20 100 50

The program prints only open ports:

TCP Port Scanner - macOS version
Target host: 127.0.0.1
Resolved IP: 127.0.0.1
Port range: 1-1024
Threads: 50
Timeout: 300 ms

Scanning...

Open ports:
  22/tcp open
  80/tcp open

Scan completed in 352 ms.
How it works

The scanner first resolves the target hostname using getaddrinfo().

Then it starts multiple worker threads.

Instead of assigning a fixed block of ports to each thread, the program uses an atomic counter:

std::atomic<int> nextPort;

Each worker thread takes the next available port using:

int port = nextPort.fetch_add(1);

This prevents two threads from scanning the same port.

For every port, the scanner creates a TCP socket and sets it to non-blocking mode using fcntl().

Then it calls connect().

Because the socket is non-blocking, connect() usually returns immediately with EINPROGRESS. This means the connection attempt has started but has not completed yet.

The scanner then uses select() to wait until the socket becomes writable or the timeout expires.

Finally, getsockopt() with SO_ERROR is used to check whether the connection actually succeeded.

If the connection succeeded, the port is considered open.

Open ports are stored in a shared vector:

std::vector<int> openPorts;

Since multiple threads may find open ports at the same time, access to the vector is protected with a mutex:

std::mutex resultsMutex;
Project structure
port_scanner/
├── README.md
├── .gitignore
└── src/
    └── main.cpp
Roadmap

Planned improvements:

 Add configurable timeout from command line
 Add service name detection for common ports
 Add JSON output
 Add CMake build system
 Split code into multiple files
 Add Linux testing
 Add Windows support using Winsock2
 Add cross-platform socket abstraction
Legal disclaimer

This tool is for educational purposes and authorized testing only.

Do not scan networks, systems, or hosts without permission.