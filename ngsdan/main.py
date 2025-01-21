from ngsdan import apiController
import threading
import socket

def main():
    print("My Project is running!")

# Set the UDP server parameters
UDP_IP = "127.0.0.1"  # Listen on all available network interfaces
UDP_PORT = 5014     # The port on which you want to listen

print(f"Listening for UDP messages on {UDP_IP}:{UDP_PORT}...")
    
# Create a socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the IP address and port
sock.bind((UDP_IP, UDP_PORT))

def udp_listener():
    while True:
        # Receive message from UDP socket
        data, addr = sock.recvfrom(1024)  # Buffer size of 1024 bytes
        print(f"Received message: {data} from {addr}")
        user_id = max(apiController.data_store.keys()) + 1
        apiController.data_store[user_id] = {data}
        print(f"data_store: {apiController.data_store}")

# Create threads
udp_thread = threading.Thread(target=udp_listener, args=(), daemon=True)

print(f"udp_thread: ")
# Start threads
udp_thread.start()


if __name__ == '__main__':
    main()
    apiController.app.run(debug=False)
    udp_thread.join()
