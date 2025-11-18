ShadowLink C2 Framework

### Legal Disclaimer ### 

PLEASE READ BEFORE USE

    This software is developed for educational purposes only. It is designed to demonstrate the technical concepts of network programming, operating system internals, and red team operations in a controlled environment.

    Do not use this software on systems you do not own or do not have explicit permission to test. The author takes no responsibility for any misuse of this code. Using this tool for malicious purposes is illegal.

### Project Overview ###

ShadowLink is a lightweight, custom-built Command & Control (C2) framework designed to explore the fundamentals of malware development and offensive security architecture.

The project consists of two main components:

    The Implant (Agent): A low-level executable written in C (targeting Windows), designed to run silently on the client machine.

    The Server (Listener): A multi-threaded command center written in Python, used to manage connections and issue commands.

This project demonstrates a deep understanding of the Windows API, socket programming, and memory management.

### Architecture ###

The system follows a traditional Client-Server architecture (Reverse TCP Shell).
Extrait de code

graph LR
    A[Attacker/Server] -- TCP Connection --> B((Internet/Network))
    B -- Commands --> C[Victim/Agent]
    C -- Shell Output --> B
    B -- Data --> A
    
    subgraph "Python Controller"
    A
    end
    
    subgraph "Windows Target"
    C
    end

### Development Roadmap (Implementation Stages) ###

This project is built in iterative sprints, moving from basic connectivity to advanced persistence mechanisms.

Phase 1: The Handshake (Connectivity)

    Goal: Establish a stable TCP connection between the C agent and the Python server.

    Technical Focus:

        Python: Socket creation (socket, bind, listen).

        C: Winsock2 initialization (WSAStartup), socket creation, and connection logic.

        Resilience: Implementing reconnection logic (beaconing) if the server is unreachable.

Phase 2: Remote Command Execution

    Goal: Ability to execute shell commands on the target and retrieve the output.

    Technical Focus:

        C: Utilizing CreateProcess (Windows API) instead of system().

        Pipes: Managing STDIN, STDOUT, and STDERR via anonymous pipes to redirect command output back to the socket without creating visible windows.

        Protocol: Designing a custom packet structure (Header + Payload) to handle data fragmentation.

Phase 3: Concurrency & Command Center

    Goal: Managing multiple agents simultaneously via a CLI.

    Technical Focus:

        Python: Implementing threading to handle each incoming connection in a separate thread.

        UI: Creating a CLI menu to list active sessions, switch targets, and broadcast commands.

Phase 4: Evasion & Persistence (Advanced)

    Goal: ensuring the agent survives reboots and evades basic detection.

    Technical Focus:

        Persistence: Manipulating the Windows Registry (HKCU\...\Run) using RegOpenKeyEx and RegSetValueEx.

        OpSec: Implementing XOR encryption for network traffic to evade basic packet inspection (Wireshark).


