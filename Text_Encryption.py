import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import random
import string
import codecs
from collections import Counter

def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


def reverse_cipher(text):
    return text[::-1]


def rot13_cipher(text):
    return codecs.encode(text, 'rot_13')


def letter_frequency_analysis(text):
    letters = [c.lower() for c in text if c.isalpha()]
    count = Counter(letters)
    return sorted(count.items(), key=lambda x: -x[1])


def perform_encryption():
    msg = input_text.get("1.0", tk.END).strip()
    shift = shift_var.get()
    cipher_type = cipher_var.get()

    if not msg:
        messagebox.showwarning("No Input", "Please enter a message.")
        return

    if cipher_type == "Caesar Cipher":
        encrypted = caesar_cipher(msg, shift)
    elif cipher_type == "Reverse Cipher":
        encrypted = reverse_cipher(msg)
    elif cipher_type == "ROT13 Cipher":
        encrypted = rot13_cipher(msg)
    else:
        encrypted = msg

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted)


def perform_decryption():
    msg = input_text.get("1.0", tk.END).strip()
    shift = shift_var.get()
    cipher_type = cipher_var.get()

    if not msg:
        messagebox.showwarning("No Input", "Please enter a message.")
        return

    if cipher_type == "Caesar Cipher":
        decrypted = caesar_cipher(msg, shift, decrypt=True)
    elif cipher_type == "Reverse Cipher":
        decrypted = reverse_cipher(msg)
    elif cipher_type == "ROT13 Cipher":
        decrypted = rot13_cipher(msg)
    else:
        decrypted = msg

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, decrypted)


def copy_to_clipboard():
    result = output_text.get("1.0", tk.END).strip()
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        root.update()
        messagebox.showinfo("Copied", "Output copied to clipboard.")
    else:
        messagebox.showwarning("Empty Output", "Nothing to copy.")


def save_to_file():
    result = output_text.get("1.0", tk.END).strip()
    if not result:
        messagebox.showwarning("No Output", "There is nothing to save.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".txt",
                                        filetypes=[("Text Files", "*.txt")])
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(result)
        messagebox.showinfo("Saved", f"File saved to {path}")


def analyze_text():
    msg = input_text.get("1.0", tk.END).strip()
    if not msg:
        messagebox.showwarning("Empty Input", "Enter text to analyze.")
        return
    freq = letter_frequency_analysis(msg)
    analysis_window = tk.Toplevel(root)
    analysis_window.title("Frequency Analysis")
    ttk.Label(analysis_window, text="Letter Frequency Count", font=("Arial", 11, "bold")).pack(pady=10)
    output_box = tk.Text(analysis_window, width=30, height=15, wrap=tk.WORD)
    output_box.pack()
    for letter, count in freq:
        output_box.insert(tk.END, f"{letter.upper()} : {count}\n")


def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode
    bg_color = "#121212" if dark_mode else "#f0f0f0"
    fg_color = "#ffffff" if dark_mode else "#000000"
    root.configure(bg=bg_color)
    for widget in root.winfo_children():
        if isinstance(widget, (tk.Frame, ttk.Frame, tk.Text, ttk.Label)):
            widget.configure(background=bg_color, foreground=fg_color)


root = tk.Tk()
root.title("Advanced Encryption Utility")
root.geometry("700x550")
root.resizable(False, False)
dark_mode = False

ttk.Label(root, text="Enter Text:", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 0))
input_text = tk.Text(root, height=6, wrap=tk.WORD)
input_text.pack(fill=tk.X, padx=10)

options_frame = ttk.Frame(root)
options_frame.pack(pady=8)

cipher_var = tk.StringVar(value="Caesar Cipher")
ttk.Label(options_frame, text="Cipher Type:").grid(row=0, column=0, padx=5)
cipher_combo = ttk.Combobox(options_frame, textvariable=cipher_var,
                            values=["Caesar Cipher", "Reverse Cipher", "ROT13 Cipher"], width=25)
cipher_combo.grid(row=0, column=1, padx=5)

shift_var = tk.IntVar(value=3)
ttk.Label(options_frame, text="Shift:").grid(row=0, column=2, padx=5)
ttk.Spinbox(options_frame, from_=1, to=25, textvariable=shift_var, width=5).grid(row=0, column=3, padx=5)
ttk.Button(options_frame, text="Random Shift", command=lambda: shift_var.set(random.randint(1, 25))).grid(row=0, column=4, padx=5)


btn_frame = ttk.Frame(root)
btn_frame.pack(pady=10)
ttk.Button(btn_frame, text="Encrypt", command=perform_encryption).grid(row=0, column=0, padx=5)
ttk.Button(btn_frame, text="Decrypt", command=perform_decryption).grid(row=0, column=1, padx=5)
ttk.Button(btn_frame, text="Analyze Text", command=analyze_text).grid(row=0, column=2, padx=5)

ttk.Label(root, text="Output:", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10)
output_text = tk.Text(root, height=6, wrap=tk.WORD, background="#f4f4f4")
output_text.pack(fill=tk.X, padx=10, pady=5)

util_frame = ttk.Frame(root)
util_frame.pack(pady=10)
ttk.Button(util_frame, text="Copy Output", command=copy_to_clipboard).grid(row=0, column=0, padx=5)
ttk.Button(util_frame, text="Save Output", command=save_to_file).grid(row=0, column=1, padx=5)
ttk.Button(util_frame, text="Toggle Theme", command=toggle_theme).grid(row=0, column=2, padx=5)

root.mainloop()
