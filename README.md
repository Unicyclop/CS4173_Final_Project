## Files

- `alice.py`: starts Alice's client side.
- `bob.py`: starts Bob's server side.
- `crypto_utils.py`: password derivation, AES encryption/decryption, IVs,
  padding, HMAC, and per-message key updates.
- `network_utils.py`: TCP socket connection and JSON packet sending/receiving.
- `gui.py`: Dear PyGui interface for sending messages and displaying ciphertext and plaintext. Dear PyGui was seen as a better alternative to Tkinter 