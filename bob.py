"""Runs Bob's side of the program (usually server)"""

import socket
from crypto_utils import SecureChannel
from gui import ChatGUI


def main():
    """Start Bob's server side of the secure P2P messaging application."""
    # Configuration
    BOB_HOST = "localhost"
    BOB_PORT = 5555
    SHARED_PASSWORD = "secure_password_123"
    
    # Start server
    print(f"Bob: Starting server on {BOB_HOST}:{BOB_PORT}...")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((BOB_HOST, BOB_PORT))
    server_sock.listen(1)
    
    print("Bob: Waiting for Alice to connect...")
    
    try:
        client_sock, client_addr = server_sock.accept()
        print(f"Bob: Alice connected from {client_addr}")
        
        # Initialize secure channel with shared password
        channel = SecureChannel(SHARED_PASSWORD)
        
        # Start GUI
        gui = ChatGUI(client_sock, channel, title="Bob's Chat")
        gui.run()
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()