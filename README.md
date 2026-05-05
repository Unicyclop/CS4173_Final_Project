# CS 4173 Final Project (Spring 2026)

## Setup

Please install `uv` by following its [quick setup guide](https://docs.astral.sh/uv/getting-started/installation/).

Then, clone this repo to your computer by running: `git clone https://github.com/Unicyclop/CS4173_Final_Project.git`. Move your terminal into that directory by running: `cd CS4173_Final_Project`.

Install a compatible Python version and the project's dependencies by running `uv sync`.

NOTE: `uv` will automatically manage both Python and the dependencies, so you don't need to worry about what's on your computer already.

Finally, activate the virtual environment:

- Windows: `.venv\Scripts\activate`
- Linux and macOS: `. .venv/bin/activate`

You can now run the project as needed. Please note that you'll need to activate the virtual environment each time you open a new terminal/shell session. (but don't reinstall `uv` each time you open a terminal, please)
## Files

- `alice.py`: starts Alice's client side.
- `bob.py`: starts Bob's server side.
- `crypto_utils.py`: password derivation, AES encryption/decryption, IVs,
  padding, HMAC, and per-message key updates.
- `network_utils.py`: TCP socket connection and JSON packet sending/receiving.
- `gui.py`: Dear PyGui interface for sending messages and displaying ciphertext and plaintext. Dear PyGui was seen as a better alternative to Tkinter 
