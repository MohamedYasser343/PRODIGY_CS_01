# PRODIGY_CS_01
Caesar Cipher Pro is a modern, user-friendly graphical application built with Python and Tkinter that implements the classic Caesar cipher encryption technique. This tool allows users to encrypt, decrypt, and brute-force text messages intuitively, featuring light and dark themes, history tracking, and file operations.

## Features
- **Encryption & Decryption**: Encrypt or decrypt text using a specified shift value (1-25).
- **Auto-Decrypt**: Automatically decrypt encrypted text with a single click when enabled.
- **Brute Force**: Attempt decryption with all possible shifts (1-25) and display results.
- **Theme Switching**: Toggle between Light and Dark themes for a personalized experience.
- **History Tracking**: View recent operations with timestamps in a dedicated history tab.
- **Clipboard Support**: Copy results directly to the clipboard.
- **File Operations**: Load text from files and save results to files.
- **Keyboard Shortcuts**: Quick access to core functions via keyboard commands.
- **Status Bar**: Real-time feedback on operations and application state.

## Requirements
- Python 3.x
- Tkinter (usually included with Python)
- Additional libraries:
  - `clipboard` (install via `pip install clipboard`)
 

## Usage
1. Launch the application by running the script.
2. Use the "Cipher" tab to:
- Enter text in the input field.
- Set a shift value (1-25) using the spinbox.
- Click "Encrypt", "Decrypt", or "Brute Force" buttons, or use keyboard shortcuts.
- Enable "Auto-decrypt" for automatic decryption after encryption.
3. View results in the output field and copy them to the clipboard if needed.
4. Use "Load File" to import text or "Save Result" to export results.
5. Switch to the "History" tab to review past operations.
6. Toggle between Light and Dark themes using the "Toggle Theme" button.

## Keyboard Shortcuts
- `Ctrl+E`: Encrypt
- `Ctrl+D`: Decrypt
- `Ctrl+B`: Brute Force
- `Ctrl+C`: Copy Result
- `Ctrl+L`: Load File
- `Ctrl+S`: Save Result
- `Ctrl+Q`: Clear
- `Ctrl+T`: Toggle Theme
