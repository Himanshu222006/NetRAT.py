import sys
import socket
import getopt
import threading
import subprocess

# Global variables
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0

# Simple ASCII logo for NetRAT
def print_logo():
    print("""
 _   _ _____ _____ ____      _  _____ 
| \ | | ____|_   _|  _ \    / \|_   _|
|  \| |  _|   | | | |_) |  / _ \ | |
| |\  | |___  | | |  _ <  / ___ \| |
|_| \_|_____| |_| |_| \_\/_/   \_\_| 
    """)

# Usage/help function
def usage():
    print("NetRAT - Network Remote Access Tool")
    print("Usage: netrat.py -t target_host -p port")
    print("-l --listen        - listen for incoming connections")
    print("-e --execute=cmd   - execute a command upon connection")
    print("-c --command       - start an interactive shell")
    print("-u --upload=dest   - upload a file to the specified destination")
    print("Examples:")
    print("netrat.py -t 192.168.0.1 -p 5555 -l -c")
    print("netrat.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe")
    sys.exit(0)

# Parse command line arguments
def parse_arguments():
    global listen, port, execute, command, upload_destination, target

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu", ["help", "listen", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--command"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"

# Send data to the target
def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target, port))

        if buffer:
            client.send(buffer.encode())

        while True:
            response = ""
            while True:
                data = client.recv(4096)
                if not data:
                    break
                response += data.decode()

            print(response)
            buffer = input("") + "\n"
            client.send(buffer.encode())

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.close()

# Handle incoming client connections
def server_loop():
    global target
    if not target:
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(5)

    while True:
        client_socket, _ = server.accept()
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()

# Run system commands on the target
def run_command(command):
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except Exception:
        output = b"Failed to execute command."
    return output

# Handle file upload and command execution for each client
def client_handler(client_socket):
    global upload, execute, command

    if upload_destination:
        file_buffer = b""
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            file_buffer += data

        try:
            with open(upload_destination, "wb") as f:
                f.write(file_buffer)
            client_socket.send(b"File uploaded successfully.\n")
        except:
            client_socket.send(b"Failed to upload file.\n")

    if execute:
        output = run_command(execute)
        client_socket.send(output)

    if command:
        while True:
            client_socket.send(b"<NetRAT:#> ")
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024).decode()
            response = run_command(cmd_buffer)
            client_socket.send(response)

# Main function
def main():
    print_logo()
    parse_arguments()

    if not listen and target and port:
        buffer = sys.stdin.read()
        client_sender(buffer)

    if listen:
        server_loop()

if __name__ == "__main__":
    main()
