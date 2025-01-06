import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
from tkinter import ttk


def calculate_hash(file_path, algorithm):
    """Calculate the hash of the file using the specified algorithm."""
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to calculate {algorithm.upper()} hash: {e}")
        return None


def compare_hash():
    """Compare the input hash with the calculated hash."""
    input_hash = hash_input.get().strip()
    selected_algorithm = algorithm_choice.get()

    if not file_path.get():
        messagebox.showwarning("Warning", "Please select a file first.")
        return
    if not input_hash:
        messagebox.showwarning("Warning", "Please enter a hash to compare.")
        return

    # Calculate the hash using the selected algorithm
    file_hash = calculate_hash(file_path.get(), selected_algorithm)
    if not file_hash:
        return

    if file_hash == input_hash:
        messagebox.showinfo("Result", f"{selected_algorithm.upper()} Hashes Matched!")
    else:
        messagebox.showinfo("Result", f"{selected_algorithm.upper()} Hashes Do Not Match!")


def browse_file():
    """Open a file dialog to select a file."""
    file = filedialog.askopenfilename(title="Select a File")
    if file:
        handle_file_selection(file)


def handle_file_selection(file):
    """Handle file selection and calculate hashes."""
    file_path.set(file)
    # Automatically calculate hashes for display
    hashes = {algo: calculate_hash(file, algo) for algo in ['md5', 'sha1', 'sha256', 'sha512']}
    for algo, hash_value in hashes.items():
        hash_text_boxes[algo].delete("1.0", "end")
        hash_text_boxes[algo].insert("1.0", hash_value)


def string_to_hash():
    """Convert the input string to various hashes."""
    input_str = string_input.get("1.0", "end-1c")
    if not input_str:
        messagebox.showwarning("Warning", "Please enter a string.")
        return

    # Calculate hashes
    hashes = {
        'md5': hashlib.md5(input_str.encode()).hexdigest(),
        'sha1': hashlib.sha1(input_str.encode()).hexdigest(),
        'sha256': hashlib.sha256(input_str.encode()).hexdigest(),
        'sha512': hashlib.sha512(input_str.encode()).hexdigest(),
    }

    # Update labels and clipboard buttons
    for algo, hash_value in hashes.items():
        string_hash_text_boxes[algo].delete("1.0", "end")
        string_hash_text_boxes[algo].insert("1.0", hash_value)


def copy_to_clipboard(value):
    """Copy the specified value to the clipboard."""
    root.clipboard_clear()
    root.clipboard_append(value)
    root.update()
    messagebox.showinfo("Clipboard", "Hash copied to clipboard!")


def drag_and_drop(event):
    """Handle drag-and-drop file input."""
    file = event.data.strip("{}")
    handle_file_selection(file)


def toggle_dark_mode():
    """Toggle between dark and light modes."""
    if dark_mode.get():
        style.theme_use("clam")
        style.configure(".", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e")
        style.configure("TButton", background="#3a3a3a", foreground="white")
        root.configure(bg="#2e2e2e")
    else:
        style.theme_use("default")
        style.configure(".", background="SystemButtonFace", foreground="black")
        root.configure(bg="SystemButtonFace")


# Main GUI window
root = TkinterDnD.Tk()  # Use TkinterDnD for drag-and-drop functionality
root.title("Dext0r - A Simple Hash Calculator and Verifier")

# Dark Mode Toggle
dark_mode = tk.BooleanVar(value=False)
style = ttk.Style(root)

# Tabbed interface
notebook = ttk.Notebook(root)
file_tab = ttk.Frame(notebook)
string_tab = ttk.Frame(notebook)
notebook.add(file_tab, text="File Hash Verifier")
notebook.add(string_tab, text="String Hash Generator")
notebook.pack(expand=True, fill="both")

# File Hash Verifier Tab
file_path = tk.StringVar()
algorithm_choice = tk.StringVar(value="md5")
hash_input = tk.StringVar()

# File selection
ttk.Label(file_tab, text="Select File:").grid(row=0, column=0, padx=5, pady=5)
ttk.Entry(file_tab, textvariable=file_path, width=40).grid(row=0, column=1, padx=5, pady=5)
ttk.Button(file_tab, text="Browse", command=browse_file).grid(row=0, column=2, padx=5, pady=5)

# Drag-and-Drop area
drop_area = ttk.Label(file_tab, text="Drag and Drop File Here", relief="solid", padding=10)
drop_area.grid(row=1, column=0, columnspan=3, padx=5, pady=10)
drop_area.drop_target_register(DND_FILES)
drop_area.dnd_bind("<<Drop>>", drag_and_drop)

# Algorithm selection
ttk.Label(file_tab, text="Select Algorithm:").grid(row=2, column=0, padx=5, pady=5)
ttk.OptionMenu(file_tab, algorithm_choice, "md5", "md5", "sha1", "sha256", "sha512").grid(row=2, column=1, columnspan=2, padx=5, pady=5)

# Hash display
hash_text_boxes = {}
for i, algo in enumerate(['md5', 'sha1', 'sha256', 'sha512']):
    ttk.Label(file_tab, text=f"{algo.upper()}:").grid(row=i+3, column=0, sticky="w", padx=5, pady=5)
    hash_text_boxes[algo] = tk.Text(file_tab, height=2, width=60, wrap="none")
    hash_text_boxes[algo].grid(row=i+3, column=1, columnspan=2, sticky="w", padx=5, pady=5)

# Hash input and compare
ttk.Label(file_tab, text="Enter Hash to Compare:").grid(row=7, column=0, padx=5, pady=5)
ttk.Entry(file_tab, textvariable=hash_input, width=40).grid(row=7, column=1, padx=5, pady=5)
ttk.Button(file_tab, text="Compare", command=compare_hash).grid(row=7, column=2, padx=5, pady=5)

# Dark Mode Toggle
ttk.Checkbutton(root, text="Dark Mode", variable=dark_mode, command=toggle_dark_mode).pack(anchor="e", padx=10, pady=5)

# String Hash Generator Tab
string_input = tk.Text(string_tab, width=60, height=5)
string_input.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

# Generate Hashes
ttk.Button(string_tab, text="Generate Hashes", command=string_to_hash).grid(row=1, column=1, pady=10)

# Hash display for strings
string_hash_text_boxes = {}
for i, algo in enumerate(['md5', 'sha1', 'sha256', 'sha512']):
    ttk.Label(string_tab, text=f"{algo.upper()}:").grid(row=i+2, column=0, sticky="w", padx=5, pady=5)
    string_hash_text_boxes[algo] = tk.Text(string_tab, height=2, width=60, wrap="none")
    string_hash_text_boxes[algo].grid(row=i+2, column=1, padx=5, pady=5)
    ttk.Button(string_tab, text="Copy", command=lambda algo=algo: copy_to_clipboard(string_hash_text_boxes[algo].get("1.0", "end-1c"))).grid(row=i+2, column=2, padx=5, pady=5)

root.mainloop()
