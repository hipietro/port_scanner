#include <arpa/inet.h>      // inet_ntop(), sockaddr_in, htons()
#include <atomic>           // std::atomic: counter shared safely between threads
#include <cerrno>           // errno: tells us why a system call failed
#include <chrono>           // used to measure scan duration
#include <cstring>          // C string utilities, useful for low-level APIs
#include <fcntl.h>          // fcntl(): used to set a socket as non-blocking
#include <iostream>         // std::cout, std::cerr
#include <mutex>            // std::mutex, std::lock_guard
#include <netdb.h>          // getaddrinfo(): resolves hostname to IP address
#include <string>           // std::string
#include <sys/select.h>     // select(): waits for socket readiness with timeout
#include <sys/socket.h>     // socket(), connect(), getsockopt()
#include <thread>           // std::thread
#include <unistd.h>         // close(): closes POSIX file descriptors/sockets
#include <vector>           // std::vector
#include <algorithm>        // std::sort

/*
    TCP Port Scanner - macOS version

    This project is intentionally written for macOS/POSIX first.

    What the program does:

    1. The user provides:
       - target host/IP
       - start port
       - end port
       - number of threads

    2. The program resolves the hostname to an IPv4 address.

    3. Multiple worker threads scan ports in parallel.

    4. Each port is tested by trying to create a TCP connection.

    5. If the TCP connection succeeds before the timeout expires,
       the port is considered OPEN.

    6. At the end, only open ports are printed.

    Important:
    This scanner performs TCP connect scanning, not raw SYN scanning.

    A true SYN scan usually requires raw sockets and often root privileges.
    Here we use the normal OS TCP stack through connect().
*/

constexpr int DEFAULT_TIMEOUT_MS = 300;

/*
    This struct stores the target address after DNS resolution.

    sockaddr_in is the standard POSIX structure for an IPv4 address.

    It contains:
    - IP address
    - port number
    - address family, usually AF_INET for IPv4

    printableIp is just a human-readable version of the resolved IP,
    useful for printing information to the user.
*/
struct TargetAddress {
    sockaddr_in address {};
    std::string printableIp;
};

/*
    Prints how the program should be launched.

    argv[0] is the program name itself.
    Example:
        ./portscanner
*/
void printUsage(const char* programName) {
    std::cerr << "Usage:\n";
    std::cerr << "  " << programName << " <host> <start_port> <end_port> <threads>\n\n";

    std::cerr << "Example:\n";
    std::cerr << "  " << programName << " 127.0.0.1 1 1024 100\n";
    std::cerr << "  " << programName << " scanme.nmap.org 20 100 50\n";
}

/*
    Parses a string into an integer and validates its range.

    Why do we need this?

    Command-line arguments arrive as strings.
    For example, if the user runs:

        ./portscanner 127.0.0.1 1 1024 50

    argv[2] is not the integer 1.
    It is the string "1".

    This function converts it safely and rejects invalid inputs such as:
    - "abc"
    - "80abc"
    - "-1"
    - "70000"
*/
int parseIntegerInRange(
    const std::string& value,
    int minValue,
    int maxValue,
    const std::string& fieldName
) {
    try {
        size_t parsedCharacters = 0;

        /*
            std::stoi converts a string to int.

            parsedCharacters tells us how many characters were actually used.
            This lets us reject inputs like "80abc".
        */
        int parsedValue = std::stoi(value, &parsedCharacters);

        /*
            If the whole string was not consumed, the input is invalid.

            Example:
                "80"    -> valid
                "80abc" -> invalid
        */
        if (parsedCharacters != value.length()) {
            throw std::invalid_argument("Invalid numeric format");
        }

        /*
            Ports must be between 1 and 65535.
            Threads are also limited to a reasonable range.
        */
        if (parsedValue < minValue || parsedValue > maxValue) {
            throw std::out_of_range("Value out of allowed range");
        }

        return parsedValue;

    } catch (const std::exception&) {
        /*
            We throw a clearer error message for the caller.
        */
        throw std::runtime_error(
            fieldName + " must be a number between " +
            std::to_string(minValue) + " and " +
            std::to_string(maxValue)
        );
    }
}

/*
    Resolves a hostname or IP address to an IPv4 address.

    Examples:
        "127.0.0.1"       -> already an IP address
        "scanme.nmap.org" -> hostname that must be resolved through DNS

    We use getaddrinfo(), which is the modern API for DNS/address resolution.
*/
TargetAddress resolveTarget(const std::string& host) {
    /*
        hints tells getaddrinfo() what kind of address we want.

        AF_INET:
            IPv4 only.

        SOCK_STREAM:
            TCP socket.

        This keeps the first version simple.
        IPv6 can be added later as a GitHub issue.
    */
    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    /*
        getaddrinfo() writes the result into this pointer.

        It may return multiple addresses as a linked list.
        For v1, we will use the first result.
    */
    addrinfo* result = nullptr;

    int status = getaddrinfo(
        host.c_str(),  // hostname or IP as C string
        nullptr,       // service/port not needed here
        &hints,        // requested address type
        &result        // output result
    );

    /*
        status == 0 means success.
        Any other value means DNS resolution failed.
    */
    if (status != 0) {
        throw std::runtime_error(
            "Failed to resolve host '" + host + "': " + gai_strerror(status)
        );
    }

    /*
        result->ai_addr is a generic sockaddr pointer.

        Since we requested AF_INET, we know it actually points to sockaddr_in.
        So we cast it and copy the IPv4 address.
    */
    sockaddr_in resolvedAddress =
        *reinterpret_cast<sockaddr_in*>(result->ai_addr);

    /*
        inet_ntop() converts the binary IP address into a readable string.

        Example:
            binary IPv4 address -> "93.184.216.34"
    */
    char ipBuffer[INET_ADDRSTRLEN];

    const char* ipString = inet_ntop(
        AF_INET,
        &resolvedAddress.sin_addr,
        ipBuffer,
        sizeof(ipBuffer)
    );

    if (ipString == nullptr) {
        freeaddrinfo(result);
        throw std::runtime_error("Failed to convert resolved IP to string");
    }

    TargetAddress target;
    target.address = resolvedAddress;
    target.printableIp = ipString;

    /*
        getaddrinfo() allocates memory internally.
        We must free it with freeaddrinfo().
    */
    freeaddrinfo(result);

    return target;
}

/*
    Sets a socket to non-blocking mode.

    Why this matters:

    A normal connect() can block for a long time if:
    - the port is filtered
    - a firewall silently drops packets
    - the host does not reply

    That would make the scanner very slow.

    Instead, we set the socket as non-blocking.
    Then connect() returns immediately.

    After that, we use select() to wait only up to our timeout.
*/
void setSocketNonBlocking(int socketFd) {
    /*
        F_GETFL gets the current file descriptor flags.

        A socket on POSIX systems is also represented by a file descriptor.
    */
    int currentFlags = fcntl(socketFd, F_GETFL, 0);

    if (currentFlags == -1) {
        throw std::runtime_error("fcntl(F_GETFL) failed");
    }

    /*
        F_SETFL updates the flags.

        We keep the old flags and add O_NONBLOCK.
    */
    if (fcntl(socketFd, F_SETFL, currentFlags | O_NONBLOCK) == -1) {
        throw std::runtime_error("fcntl(F_SETFL) failed");
    }
}

/*
    Checks if a single TCP port is open.

    Return value:
        true  -> the port accepted the TCP connection
        false -> the port is closed, filtered, timed out, or unreachable

    This is the core networking function of the scanner.
*/
bool isTcpPortOpen(
    const TargetAddress& target,
    int port,
    int timeoutMs
) {
    /*
        Create a TCP socket.

        AF_INET:
            IPv4

        SOCK_STREAM:
            TCP

        0:
            Use the default protocol for SOCK_STREAM, which is TCP.
    */
    int socketFd = socket(AF_INET, SOCK_STREAM, 0);

    /*
        socket() returns a negative value if it fails.
        If it fails, we simply mark the port as not open.
    */
    if (socketFd < 0) {
        return false;
    }

    /*
        Make the socket non-blocking so connect() does not freeze the program.
    */
    try {
        setSocketNonBlocking(socketFd);
    } catch (const std::exception&) {
        close(socketFd);
        return false;
    }

    /*
        Every port needs a different destination address because the port changes.

        target.address already contains:
        - IPv4 address
        - address family

        We copy it and only change sin_port.
    */
    sockaddr_in connectionAddress = target.address;

    /*
        htons() converts the port number from host byte order to network byte order.

        Network protocols use big-endian byte order.
        Your Mac may store integers differently internally.
        So we must convert before putting the port into sockaddr_in.
    */
    connectionAddress.sin_port = htons(static_cast<uint16_t>(port));

    /*
        Start the TCP connection attempt.

        With a blocking socket:
            connect() waits until success/failure.

        With a non-blocking socket:
            connect() usually returns immediately.
    */
    int connectResult = connect(
        socketFd,
        reinterpret_cast<sockaddr*>(&connectionAddress),
        sizeof(connectionAddress)
    );

    /*
        If connect() returns 0, the connection succeeded immediately.

        This often happens when scanning localhost.
    */
    if (connectResult == 0) {
        close(socketFd);
        return true;
    }

    /*
        For a non-blocking socket, connect() commonly returns -1
        and sets errno to EINPROGRESS.

        EINPROGRESS does NOT mean the port is closed.

        It means:
            "The connection attempt has started,
             but it has not completed yet."
    */
    if (errno != EINPROGRESS) {
        close(socketFd);
        return false;
    }

    /*
        Now we wait for the socket to become writable.

        In the case of a non-blocking connect(),
        "writable" means the connection attempt completed.

        It may have completed successfully or with an error.
        We check that later with getsockopt().
    */
    fd_set writeSet;

    /*
        Always initialize fd_set before using it.
    */
    FD_ZERO(&writeSet);

    /*
        Add our socket to the set of descriptors we want to monitor.
    */
    FD_SET(socketFd, &writeSet);

    /*
        timeval is the timeout format expected by select().

        Example with timeoutMs = 300:
            tv_sec  = 0
            tv_usec = 300000
    */
    timeval timeout {};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;

    /*
        select() waits until:
        - the socket becomes writable
        - an error happens
        - the timeout expires

        First argument:
            socketFd + 1

        This is required by the POSIX select() API.
    */
    int selectResult = select(
        socketFd + 1,
        nullptr,     // read set: not needed
        &writeSet,   // write set: we wait for connect completion
        nullptr,     // exception set: not needed here
        &timeout     // maximum wait time
    );

    /*
        selectResult == 0:
            timeout expired

        selectResult < 0:
            select() failed

        In both cases, we treat the port as not open.
    */
    if (selectResult <= 0) {
        close(socketFd);
        return false;
    }

    /*
        If we reach this point, the socket changed state.

        But we still do not know if connect() succeeded.

        A socket can become writable even when the connection failed.
        So we ask the socket for the final connect result.
    */
    int socketError = 0;
    socklen_t socketErrorLength = sizeof(socketError);

    /*
        getsockopt(..., SO_ERROR, ...) gives the pending error on the socket.

        If socketError == 0:
            connect() succeeded

        If socketError != 0:
            connect() failed
    */
    int optionResult = getsockopt(
        socketFd,
        SOL_SOCKET,
        SO_ERROR,
        &socketError,
        &socketErrorLength
    );

    /*
        We are done with this socket.
        Always close it to avoid leaking file descriptors.
    */
    close(socketFd);

    if (optionResult < 0) {
        return false;
    }

    /*
        socketError == 0 means the TCP handshake completed successfully.
        Therefore, the port is open.
    */
    return socketError == 0;
}

/*
    Worker function executed by each thread.

    Each worker repeatedly asks:
        "What is the next port I should scan?"

    The answer comes from nextPort, an atomic integer.

    Why atomic?

    Without atomic, two threads could read the same port value at the same time.
    Example:
        Thread A reads 80
        Thread B also reads 80

    Then both scan the same port, which is wrong and wasteful.

    nextPort.fetch_add(1) guarantees that each thread receives a unique port.
*/
void scanWorker(
    const TargetAddress& target,
    int endPort,
    int timeoutMs,
    std::atomic<int>& nextPort,
    std::vector<int>& openPorts,
    std::mutex& resultsMutex
) {
    while (true) {
        /*
            Atomically get the current port and increment the counter.

            Example:
                nextPort starts at 20

                Thread A gets 20, nextPort becomes 21
                Thread B gets 21, nextPort becomes 22
                Thread C gets 22, nextPort becomes 23
        */
        int port = nextPort.fetch_add(1);

        /*
            If we passed the end of the range, this worker is done.
        */
        if (port > endPort) {
            break;
        }

        /*
            Scan the selected port.
        */
        if (isTcpPortOpen(target, port, timeoutMs)) {
            /*
                openPorts is shared by all threads.

                Multiple threads could try to push_back() at the same time.
                That would be a race condition.

                The mutex ensures that only one thread at a time can modify
                the vector.
            */
            std::lock_guard<std::mutex> lock(resultsMutex);
            openPorts.push_back(port);
        }
    }
}

int main(int argc, char* argv[]) {
    /*
        argc is the number of command-line arguments.

        Expected:
            argv[0] -> program name
            argv[1] -> host
            argv[2] -> start port
            argv[3] -> end port
            argv[4] -> thread count

        So argc must be 5.
    */
    if (argc != 5) {
        printUsage(argv[0]);
        return 1;
    }

    try {
        /*
            Read the host from the command line.
        */
        std::string host = argv[1];

        /*
            Parse and validate numeric arguments.
        */
        int startPort = parseIntegerInRange(argv[2], 1, 65535, "start_port");
        int endPort = parseIntegerInRange(argv[3], 1, 65535, "end_port");
        int threadCount = parseIntegerInRange(argv[4], 1, 500, "threads");

        /*
            The starting port must not be greater than the ending port.
        */
        if (startPort > endPort) {
            throw std::runtime_error("start_port cannot be greater than end_port");
        }

        int totalPorts = endPort - startPort + 1;

        /*
            Avoid creating more threads than ports.

            Example:
                scanning ports 80-85 means only 6 ports.
                Creating 100 threads would be useless.
        */
        if (threadCount > totalPorts) {
            threadCount = totalPorts;
        }

        /*
            Resolve hostname/IP before starting the scan.

            If the hostname is invalid, we fail early.
        */
        TargetAddress target = resolveTarget(host);

        std::cout << "TCP Port Scanner - macOS version\n";
        std::cout << "Target host: " << host << "\n";
        std::cout << "Resolved IP: " << target.printableIp << "\n";
        std::cout << "Port range: " << startPort << "-" << endPort << "\n";
        std::cout << "Threads: " << threadCount << "\n";
        std::cout << "Timeout: " << DEFAULT_TIMEOUT_MS << " ms\n\n";
        std::cout << "Scanning...\n\n";

        /*
            Start measuring execution time.
        */
        auto startTime = std::chrono::steady_clock::now();

        /*
            Atomic counter used to distribute work between threads.

            It starts at startPort.
            Each thread increments it when it takes a port.
        */
        std::atomic<int> nextPort(startPort);

        /*
            Shared vector containing only open ports.

            It must be protected with a mutex when modified.
        */
        std::vector<int> openPorts;

        /*
            Mutex used to protect openPorts.
        */
        std::mutex resultsMutex;

        /*
            Vector containing all worker thread objects.

            We keep them here so we can join them later.
        */
        std::vector<std::thread> workers;

        /*
            Launch worker threads.

            std::cref(target):
                pass target by const reference

            std::ref(nextPort), std::ref(openPorts), std::ref(resultsMutex):
                pass these objects by reference

            This is necessary because std::thread copies arguments by default.
        */
        for (int i = 0; i < threadCount; ++i) {
            workers.emplace_back(
                scanWorker,
                std::cref(target),
                endPort,
                DEFAULT_TIMEOUT_MS,
                std::ref(nextPort),
                std::ref(openPorts),
                std::ref(resultsMutex)
            );
        }

        /*
            Wait for all threads to finish.

            join() blocks the main thread until the worker completes.

            Without join(), main could finish while worker threads are still running.
        */
        for (std::thread& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        /*
            Stop measuring execution time.
        */
        auto endTime = std::chrono::steady_clock::now();

        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime
        ).count();

        /*
            Ports may be discovered in random order because threads run in parallel.

            Sorting gives clean output.
        */
        std::sort(openPorts.begin(), openPorts.end());

        /*
            Print only open ports.
        */
        std::cout << "Open ports:\n";

        if (openPorts.empty()) {
            std::cout << "  No open ports found.\n";
        } else {
            for (int port : openPorts) {
                std::cout << "  " << port << "/tcp open\n";
            }
        }

        std::cout << "\nScan completed in " << elapsedMs << " ms.\n";

    } catch (const std::exception& exception) {
        /*
            Any validation or runtime error ends up here.

            We print the error and then show correct usage.
        */
        std::cerr << "Error: " << exception.what() << "\n\n";
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}