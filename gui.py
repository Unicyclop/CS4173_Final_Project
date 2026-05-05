"""Dear PyGui interface for the Secure P2P Messaging project.

The GUI shows:
- plaintext typed by the local user
- ciphertext generated when sending
- ciphertext received from the peer
- decrypted plaintext recovered after decryption
"""

from __future__ import annotations

import socket
import threading
from typing import Any, Dict

import dearpygui.dearpygui as dpg

from crypto_utils import SecureChannel
from network_utils import receive_json, send_json

class ChatGUI:
    """Dear PyGui chat window used by Alice and Bob."""

    def __init__(self, sock: socket.socket, channel: SecureChannel, title: str):
        self.sock = sock
        self.channel = channel
        self.title = title
        self.running = True
        self.log_lines: list[str] = []

    def append_log(self, text: str) -> None:
        """Add a line to the chat display."""
        self.log_lines.append(text)
        dpg.set_value("chat_log", "\n".join(self.log_lines))

    def update_status(self) -> None:
        dpg.set_value("status_text", f"Connected. Key epoch: {self.channel.current_key_epoch()}")

    @staticmethod
    def short_ciphertext(packet: Dict[str, Any]) -> str:
        """Return the ciphertext field shown in the GUI/report screenshots."""
        return str(packet["ciphertext"])

    def send_message(self) -> None:
        """Encrypt and send the message currently typed in the input box."""
        plaintext = dpg.get_value("message_input").strip()
        if not plaintext:
            return

        try:
            packet = self.channel.encrypt_message(plaintext)
            send_json(self.sock, packet)
            print("DEBUG - Sending encrypted packet:", packet)
            dpg.set_value("message_input", "")
            self.update_status()
            self.append_log(f"[Key Update] Current epoch: {self.channel.current_key_epoch()}")
            self.append_log(f"ME plaintext: {plaintext}")
            self.append_log(f"ME sent ciphertext: {self.short_ciphertext(packet)}")
            self.append_log("-" * 80)
        except Exception as exc:  # GUI callback should not crash the app
            self.append_log(f"Send error: {exc}")

    def receive_loop(self) -> None:
        """Receive encrypted packets in a background thread."""
        while self.running:
            try:
                packet = receive_json(self.sock)
                plaintext = self.channel.decrypt_message(packet)
                print("DEBUG - Key epoch:", self.channel.current_key_epoch())
                print("DEBUG - Received encrypted packet:", packet)
                print("DEBUG - Decrypted plaintext:", plaintext)
                dpg.set_value("pending_received_ciphertext", self.short_ciphertext(packet))
                dpg.set_value("pending_received_plaintext", plaintext)
            except Exception as exc:
                if self.running:
                    dpg.set_value("pending_error", f"Connection/error: {exc}")
                break

    def poll_received_values(self) -> None:
        """Move background-thread updates safely into the visible GUI log."""
        error = dpg.get_value("pending_error")
        if error:
            dpg.set_value("pending_error", "")
            self.append_log(error)
            return

        ciphertext = dpg.get_value("pending_received_ciphertext")
        plaintext = dpg.get_value("pending_received_plaintext")
        if ciphertext or plaintext:
            dpg.set_value("pending_received_ciphertext", "")
            dpg.set_value("pending_received_plaintext", "")
            self.append_log(f"RECEIVED ciphertext: {ciphertext}")
            self.append_log(f"RECEIVED decrypted plaintext: {plaintext}")
            self.append_log("-" * 80)

    def close(self) -> None:
        """Stop the GUI and close the socket."""
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass
        dpg.stop_dearpygui()

    def run(self) -> None:
        """Build and run the Dear PyGui event loop."""
        dpg.create_context()

        with dpg.window(label=self.title, tag="main_window", width=850, height=620):
            dpg.add_text(self.title)
            dpg.add_text(f"Connected. Key epoch: {self.channel.current_key_epoch()}", tag="status_text")
            dpg.add_separator()

            dpg.add_input_text(
                tag="chat_log",
                multiline=True,
                readonly=True,
                width=820,
                height=430,
                default_value="",
            )

            dpg.add_input_text(
                label="Message",
                tag="message_input",
                width=700,
                on_enter=True,
                callback=lambda: self.send_message(),
            )
            dpg.add_same_line()
            dpg.add_button(label="Send", width=90, callback=lambda: self.send_message())

            # Hidden fields used to pass data from the socket thread into the GUI loop.
            dpg.add_input_text(tag="pending_received_ciphertext", show=False, default_value="")
            dpg.add_input_text(tag="pending_received_plaintext", show=False, default_value="")
            dpg.add_input_text(tag="pending_error", show=False, default_value="")

            dpg.add_button(label="Close", callback=lambda: self.close())

        dpg.create_viewport(title=self.title, width=880, height=660)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("main_window", True)

        threading.Thread(target=self.receive_loop, daemon=True).start()

        while dpg.is_dearpygui_running() and self.running:
            self.poll_received_values()
            dpg.render_dearpygui_frame()

        self.close()
        dpg.destroy_context()

        