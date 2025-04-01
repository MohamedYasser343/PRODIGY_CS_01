import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import clipboard
import datetime

class CaesarCipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Caesar Cipher Pro")
        self.root.geometry("600x750")
        self.root.resizable(False, False)
        
        # History and settings
        self.history = []
        self.theme = "Light"
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=3)
        
        # Main container
        self.main_frame = ttk.Frame(root, padding="15")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Create themed notebook (tabs)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        
        # Cipher tab
        self.cipher_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.cipher_frame, text="Cipher")
        
        # History tab
        self.history_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.history_frame, text="History")
        
        # Setup UI components
        self.setup_cipher_tab()
        self.setup_history_tab()
        self.setup_status_bar()
        self.configure_theme()
        
        # Keyboard shortcuts
        self.bind_shortcuts()

    def setup_cipher_tab(self):
        # Title
        ttk.Label(self.cipher_frame, text="Caesar Cipher Pro", 
                 font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 15))
        
        # Input Section
        input_frame = ttk.LabelFrame(self.cipher_frame, text="Input", padding="5")
        input_frame.grid(row=1, column=0, columnspan=2, pady=5, sticky="ew")
        
        self.message_text = tk.Text(input_frame, height=6, width=60, wrap="word")
        self.message_text.grid(row=0, column=0, pady=5, padx=5)
        scrollbar = ttk.Scrollbar(input_frame, orient="vertical", command=self.message_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.message_text.configure(yscrollcommand=scrollbar.set)
        
        # Controls Section
        controls_frame = ttk.LabelFrame(self.cipher_frame, text="Controls", padding="5")
        controls_frame.grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")
        
        ttk.Label(controls_frame, text="Shift (1-25):").grid(row=0, column=0, padx=5)
        self.shift_entry = ttk.Spinbox(controls_frame, from_=1, to=25, width=5)
        self.shift_entry.grid(row=0, column=1, padx=5)
        self.auto_var = tk.BooleanVar()
        ttk.Checkbutton(controls_frame, text="Auto-decrypt", 
                       variable=self.auto_var).grid(row=0, column=2, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(controls_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=10)
        buttons = [
            ("Encrypt", self.encrypt), ("Decrypt", self.decrypt),
            ("Brute Force", self.brute_force), ("Copy", self.copy_result)
        ]
        for i, (text, cmd) in enumerate(buttons):
            ttk.Button(button_frame, text=text, command=cmd).grid(row=0, column=i, padx=5)
        
        # Output Section
        output_frame = ttk.LabelFrame(self.cipher_frame, text="Result", padding="5")
        output_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")
        
        self.result_text = tk.Text(output_frame, height=6, width=60, wrap="word", state="disabled")
        self.result_text.grid(row=0, column=0, pady=5, padx=5)
        scrollbar2 = ttk.Scrollbar(output_frame, orient="vertical", command=self.result_text.yview)
        scrollbar2.grid(row=0, column=1, sticky="ns")
        self.result_text.configure(yscrollcommand=scrollbar2.set)
        
        # File Operations
        file_frame = ttk.Frame(self.cipher_frame)
        file_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(file_frame, text="Load File", command=self.load_file).grid(row=0, column=0, padx=5)
        ttk.Button(file_frame, text="Save Result", command=self.save_file).grid(row=0, column=1, padx=5)
        ttk.Button(file_frame, text="Clear", command=self.clear).grid(row=0, column=2, padx=5)
        ttk.Button(file_frame, text="Toggle Theme", command=self.toggle_theme).grid(row=0, column=3, padx=5)

    def setup_history_tab(self):
        self.history_listbox = tk.Listbox(self.history_frame, height=20, width=60)
        self.history_listbox.grid(row=0, column=0, pady=5, padx=5)
        scrollbar = ttk.Scrollbar(self.history_frame, orient="vertical", command=self.history_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.history_listbox.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(self.history_frame, text="Clear History", 
                  command=lambda: [self.history.clear(), self.update_history()]).grid(row=1, column=0, pady=5)

    def setup_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, 
                             relief="sunken", anchor="w", padding=5)
        status_bar.grid(row=1, column=0, sticky="ew")

    def configure_theme(self):
        if self.theme == "Light":
            bg, fg = "#f0f0f0", "#333333"
            input_bg, result_bg = "#ffffff", "#e6ffe6"
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", foreground=fg, background=bg)
            self.style.configure("TButton", background="#e0e0e0")
        else:
            bg, fg = "#2d2d2d", "#ffffff"
            input_bg, result_bg = "#404040", "#304030"
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", foreground=fg, background=bg)
            self.style.configure("TButton", background="#4d4d4d")
        
        # Configure Text widgets (support insertbackground)
        self.message_text.config(bg=input_bg, fg=fg, insertbackground=fg)
        self.result_text.config(bg=result_bg, fg=fg, insertbackground=fg)
        # Configure Listbox separately (no insertbackground)
        self.history_listbox.config(bg=input_bg, fg=fg)

    def bind_shortcuts(self):
        shortcuts = {
            "<Control-e>": self.encrypt, "<Control-d>": self.decrypt,
            "<Control-c>": self.copy_result, "<Control-l>": self.load_file,
            "<Control-s>": self.save_file, "<Control-q>": self.clear,
            "<Control-b>": self.brute_force, "<Control-t>": self.toggle_theme
        }
        for key, cmd in shortcuts.items():
            self.root.bind(key, lambda e, c=cmd: c())

    def caesar_cipher(self, text, shift, decrypt=False):
        result = ""
        shift = -shift if decrypt else shift
        for char in text:
            if char.isalpha():
                ascii_base = 65 if char.isupper() else 97
                shifted_position = (ord(char) - ascii_base + shift) % 26
                result += chr(shifted_position + ascii_base)
            else:
                result += char
        return result

    def validate_shift(self):
        try:
            shift = int(self.shift_entry.get())
            if 1 <= shift <= 25:
                return shift
            else:
                messagebox.showerror("Error", "Shift value must be between 1 and 25")
                return None
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number")
            return None

    def encrypt(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty")
            return
        shift = self.validate_shift()
        if shift is not None:
            result = self.caesar_cipher(message, shift)
            self.display_result(result, "Encrypted")
            if self.auto_var.get():
                self.decrypt_auto(result, shift)

    def decrypt(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty")
            return
        shift = self.validate_shift()
        if shift is not None:
            result = self.caesar_cipher(message, shift, decrypt=True)
            self.display_result(result, "Decrypted")

    def decrypt_auto(self, encrypted, shift):
        result = self.caesar_cipher(encrypted, shift, decrypt=True)
        self.display_result(result, "Auto-Decrypted")

    def brute_force(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty")
            return
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        for shift in range(1, 26):
            result = self.caesar_cipher(message, shift, decrypt=True)
            self.result_text.insert(tk.END, f"Shift {shift:2d}: {result[:50]}{'...' if len(result) > 50 else ''}\n")
        self.result_text.config(state="disabled")
        self.history.append(f"Brute Force: {message[:30]}{'...' if len(message) > 30 else ''}")
        self.update_history()
        self.status_var.set("Brute Force completed")

    def display_result(self, result, action):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", result)
        self.result_text.config(state="disabled")
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.history.append(f"{action} [{timestamp}]: {result[:50]}{'...' if len(result) > 50 else ''}")
        self.update_history()
        self.status_var.set(f"{action} at {timestamp}")

    def update_history(self):
        self.history_listbox.delete(0, tk.END)
        for item in self.history[-20:]:
            self.history_listbox.insert(tk.END, item)

    def copy_result(self):
        result = self.result_text.get("1.0", tk.END).strip()
        if result:
            clipboard.copy(result)
            messagebox.showinfo("Success", "Result copied to clipboard")
            self.status_var.set("Copied to clipboard")

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.message_text.delete("1.0", tk.END)
                    self.message_text.insert("1.0", content)
                self.status_var.set(f"Loaded {file_path.split('/')[-1]}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def save_file(self):
        result = self.result_text.get("1.0", tk.END).strip()
        if not result:
            messagebox.showerror("Error", "No result to save")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                               filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(result)
                messagebox.showinfo("Success", "Result saved successfully")
                self.status_var.set(f"Saved to {file_path.split('/')[-1]}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

    def clear(self):
        self.message_text.delete("1.0", tk.END)
        self.shift_entry.delete(0, tk.END)
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        self.status_var.set("Cleared")

    def toggle_theme(self):
        self.theme = "Dark" if self.theme == "Light" else "Light"
        self.configure_theme()
        self.status_var.set(f"Switched to {self.theme} theme")

if __name__ == "__main__":
    root = tk.Tk()
    app = CaesarCipherGUI(root)
    root.mainloop()
