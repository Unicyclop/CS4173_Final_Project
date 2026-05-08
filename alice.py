"""Runs Alice's side of the program (usually client)"""

import socket
from crypto_utils import SecureChannel
from gui import ChatGUI


def main():
    """Start Alice's client side of the secure P2P messaging application."""
    # Configuration
    BOB_HOST = "localhost"
    BOB_PORT = 5555
    SHARED_PASSWORD = "secure_password_123"
    
    # Connect to Bob's server
    print(f"Alice: Connecting to Bob at {BOB_HOST}:{BOB_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect((BOB_HOST, BOB_PORT))
        print("Alice: Connected to Bob!")
        
        # Initialize secure channel with shared password
        channel = SecureChannel(SHARED_PASSWORD)
        
        # Start GUI
        gui = ChatGUI(sock, channel, title="Alice's Chat")
        gui.run()
        
    except ConnectionRefusedError:
        print(f"Error: Could not connect to Bob at {BOB_HOST}:{BOB_PORT}")
        print("Make sure Bob's server is running first!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()