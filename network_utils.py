"""Handles socket connection:
- start server
- connect client
- send encrypted message
- receive encrypted message"""

import json
import socket
from typing import Any, Dict


def send_json(sock: socket.socket, data: Dict[str, Any]) -> None:
    """Send a JSON-serialized dictionary over a socket.
    
    Encodes the dictionary as JSON and sends it followed by a newline delimiter.
    
    Args:
        sock: Socket to send data on.
        data: Dictionary to serialize and send.
        
    Raises:
        socket.error: If sending fails.
    """
    json_str = json.dumps(data)
    sock.sendall((json_str + "\n").encode("utf-8"))


def receive_json(sock: socket.socket) -> Dict[str, Any]:
    """Receive a JSON-serialized dictionary from a socket.
    
    Reads data from socket until a newline delimiter is found, then parses as JSON.
    
    Args:
        sock: Socket to receive data from.
        
    Returns:
        Parsed dictionary from received JSON.
        
    Raises:
        socket.error: If receiving fails.
        json.JSONDecodeError: If received data is not valid JSON.
    """
    buffer = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("Socket connection closed")
        buffer += chunk
        
        # Look for newline delimiter
        if b"\n" in buffer:
            line, remainder = buffer.split(b"\n", 1)
            # Note: remainder is discarded; only process one line at a time
            json_str = line.decode("utf-8")
            return json.loads(json_str)