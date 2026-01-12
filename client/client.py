import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import socket
import threading
import sys
import os
from datetime import datetime
import time
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import *
from common.protocol import *
from common.encryption import encrypt, decrypt
from common.file_handler import (
    validate_file, get_file_info, FileReader, FileWriter,
    format_file_size, open_file_location
)


# ==================== LOGIN DIALOG ====================

class LoginDialog:
    """Discord-themed login dialog."""
    
    def __init__(self, parent):
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Login - Chat Application")
        self.dialog.geometry("450x400")
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=BG_COLOR)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - 225
        y = (self.dialog.winfo_screenheight() // 2) - 200
        self.dialog.geometry(f"450x400+{x}+{y}")
        
        self.create_widgets()
        self.username_entry.focus()
    
    def create_widgets(self):
        """Create modern login form."""
        title_frame = tk.Frame(self.dialog, bg=BG_COLOR)
        title_frame.pack(pady=30)
        
        title_label = tk.Label(
            title_frame,
            text="💬 Chat Application",
            font=(FONT_FAMILY, FONT_SIZE_TITLE, "bold"),
            bg=BG_COLOR,
            fg=ACCENT_COLOR
        )
        title_label.pack()
        
        subtitle = tk.Label(
            title_frame,
            text="Connect with your team",
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            bg=BG_COLOR,
            fg=TEXT_SECONDARY
        )
        subtitle.pack()
        
        form_frame = tk.Frame(self.dialog, bg=BG_COLOR)
        form_frame.pack(pady=10, padx=40, fill="both")
        
        self.create_input_field(form_frame, "SERVER ADDRESS", DEFAULT_SERVER_IP, var_name='server')
        
        port_frame = tk.Frame(form_frame, bg=BG_COLOR)
        port_frame.pack(fill="x", pady=5)
        
        tk.Label(
            port_frame,
            text="PORT",
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
            bg=BG_COLOR,
            fg=TEXT_SECONDARY
        ).pack(anchor="w")
        
        self.port_entry = tk.Entry(
            port_frame,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            bg=INPUT_BG_COLOR,
            fg=TEXT_COLOR,
            relief="flat",
            insertbackground=TEXT_COLOR,
            width=10
        )
        self.port_entry.insert(0, str(DEFAULT_TCP_PORT))
        self.port_entry.pack(fill="x", ipady=8)
        
        self.create_input_field(form_frame, "USERNAME", "", var_name='username')
        
        tk.Label(
            form_frame,
            text="PASSWORD",
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
            bg=BG_COLOR,
            fg=TEXT_SECONDARY
        ).pack(anchor="w", pady=(10, 5))
        
        self.password_entry = tk.Entry(
            form_frame,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            bg=INPUT_BG_COLOR,
            fg=TEXT_COLOR,
            relief="flat",
            insertbackground=TEXT_COLOR,
            show="●"
        )
        self.password_entry.pack(fill="x", ipady=8)
        
        login_btn = tk.Button(
            form_frame,
            text="Login",
            command=self.on_login,
            bg=BUTTON_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
            relief="flat",
            cursor="hand2",
            activebackground=BUTTON_HOVER,
            activeforeground=TEXT_COLOR
        )
        login_btn.pack(fill="x", ipady=12, pady=(20, 5))
        
        self.dialog.bind('<Return>', lambda e: self.on_login())
        
        info_frame = tk.Frame(self.dialog, bg=SIDEBAR_COLOR)
        info_frame.pack(fill="x", side="bottom")
        
        info_text = "Demo accounts: alice/password123 • bob/securepass • demo/demo"
        tk.Label(
            info_frame,
            text=info_text,
            bg=SIDEBAR_COLOR,
            fg=TEXT_SECONDARY,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            pady=15
        ).pack()
    
    def create_input_field(self, parent, label, default, var_name=None):
        """Create labeled input field."""
        tk.Label(
            parent,
            text=label,
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
            bg=BG_COLOR,
            fg=TEXT_SECONDARY
        ).pack(anchor="w", pady=(10, 5))
        
        entry = tk.Entry(
            parent,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            bg=INPUT_BG_COLOR,
            fg=TEXT_COLOR,
            relief="flat",
            insertbackground=TEXT_COLOR
        )
        if default:
            entry.insert(0, default)
        entry.pack(fill="x", ipady=8)
        
        if var_name:
            setattr(self, f'{var_name}_entry', entry)
    
    def on_login(self):
        """Handle login."""
        server = self.server_entry.get().strip()
        port = self.port_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not all([server, port, username, password]):
            messagebox.showerror("Error", "Please fill all fields", parent=self.dialog)
            return
        
        try:
            port = int(port)
            if not (1024 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Invalid port number", parent=self.dialog)
            return
        
        self.result = {
            'server': server,
            'port': port,
            'username': username,
            'password': password
        }
        self.dialog.destroy()
    
    def show(self):
        """Show dialog and wait."""
        self.dialog.wait_window()
        return self.result


# ==================== MAIN CHAT CLIENT ====================

class ChatClient:
    """Main chat client with Discord dark theme and enhanced features."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.minsize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self.root.configure(bg=BG_COLOR)
        
        # Network
        self.socket = None
        self.connected = False
        self.username = None
        self.password = None  # Store for reconnect
        
        # Message buffer
        self.message_buffer = MessageBuffer()
        
        # File transfer state
        self.active_file_writer = None
        self.active_file_reader = None
        self.file_progress_bar = None
        self.receiving_file = False
        self.file_buffer = b''
        self.expected_file_size = 0
        self.current_filename = ""
        
        # NEW: Typing and status tracking
        self.typing_timer = None
        self.is_typing = False
        self.typing_users = set()
        self.user_statuses = {}
        self.session_id = None
        self.my_status = STATUS_ONLINE
        self.last_message_date = None
        
        # Threading
        self.receive_thread = None
        self.send_file_thread = None
        self.running = False
        
        # Show login
        if not self.show_login():
            self.root.destroy()
            return
        
        # Create GUI
        self.create_widgets()
        
        # Connect
        self.connect_to_server()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def show_login(self) -> bool:
        """Show login dialog."""
        dialog = LoginDialog(self.root)
        credentials = dialog.show()
        
        if not credentials:
            return False
        
        self.server_ip = credentials['server']
        self.server_port = credentials['port']
        self.username = credentials['username']
        self.password = credentials['password']
        
        return True
    
    def create_widgets(self):
        """Create Discord-themed chat interface."""
        main_frame = tk.Frame(self.root, bg=BG_COLOR)
        main_frame.pack(fill="both", expand=True)
        
        # LEFT SIDEBAR
        sidebar = tk.Frame(main_frame, bg=SIDEBAR_COLOR, width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        
        server_label = tk.Label(
            sidebar,
            text="💬 Chat Server",
            font=(FONT_FAMILY, FONT_SIZE_LARGE, "bold"),
            bg=SIDEBAR_COLOR,
            fg=TEXT_COLOR,
            pady=15
        )
        server_label.pack(fill="x")
        
        ttk.Separator(sidebar, orient='horizontal').pack(fill='x', padx=10)
        
        # NEW: Status selector
        status_frame = tk.Frame(sidebar, bg=SIDEBAR_COLOR)
        status_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(
            status_frame,
            text="YOUR STATUS",
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
            bg=SIDEBAR_COLOR,
            fg=TEXT_SECONDARY
        ).pack(anchor="w", pady=(0, 5))
        
        self.status_var = tk.StringVar(value=STATUS_ONLINE)
        
        for text, value in [("🟢 Online", STATUS_ONLINE), ("🔴 Busy", STATUS_BUSY)]:
            rb = tk.Radiobutton(
                status_frame,
                text=text,
                variable=self.status_var,
                value=value,
                bg=SIDEBAR_COLOR,
                fg=TEXT_COLOR,
                selectcolor=SIDEBAR_COLOR,
                activebackground=SIDEBAR_COLOR,
                activeforeground=TEXT_COLOR,
                command=self.change_status,
                font=(FONT_FAMILY, FONT_SIZE_SMALL)
            )
            rb.pack(anchor="w")
        
        ttk.Separator(sidebar, orient='horizontal').pack(fill='x', padx=10, pady=10)
        
        users_header = tk.Label(
            sidebar,
            text="ONLINE USERS",
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
            bg=SIDEBAR_COLOR,
            fg=TEXT_SECONDARY,
            pady=10
        )
        users_header.pack(fill="x", padx=10)
        
        users_frame = tk.Frame(sidebar, bg=SIDEBAR_COLOR)
        users_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.users_listbox = tk.Listbox(
            users_frame,
            bg=SIDEBAR_COLOR,
            fg=TEXT_COLOR,
            selectmode="single",
            relief="flat",
            highlightthickness=0,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            selectbackground=ACCENT_COLOR
        )
        self.users_listbox.pack(fill="both", expand=True)
        
        btn_frame = tk.Frame(sidebar, bg=SIDEBAR_COLOR)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        self.create_sidebar_button(btn_frame, "⚡ Buzz", self.send_buzz, BUZZ_COLOR)
        self.create_sidebar_button(btn_frame, "📁 Send File", self.send_file, ACCENT_COLOR)
        
        # CHAT AREA
        chat_frame = tk.Frame(main_frame, bg=CHAT_BG_COLOR)
        chat_frame.pack(side="left", fill="both", expand=True)
        
        header = tk.Frame(chat_frame, bg=BG_COLOR, height=50)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        channel_label = tk.Label(
            header,
            text=f"# general",
            font=(FONT_FAMILY, FONT_SIZE_LARGE, "bold"),
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            anchor="w"
        )
        channel_label.pack(side="left", padx=20, fill="both", expand=True)
        
        user_info = tk.Label(
            header,
            text=f"👤 {self.username}",
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            bg=BG_COLOR,
            fg=TEXT_SECONDARY
        )
        user_info.pack(side="right", padx=20)
        
        ttk.Separator(chat_frame, orient='horizontal').pack(fill='x')
        
        chat_container = tk.Frame(chat_frame, bg=CHAT_BG_COLOR)
        chat_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_container,
            wrap=tk.WORD,
            state="disabled",
            bg=CHAT_BG_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            relief="flat",
            insertbackground=TEXT_COLOR,
            selectbackground=ACCENT_COLOR
        )
        self.chat_display.pack(fill="both", expand=True)
        
        # Configure tags
        self.chat_display.tag_config("timestamp", foreground=TEXT_SECONDARY, font=(FONT_FAMILY, FONT_SIZE_SMALL))
        self.chat_display.tag_config("self", foreground=MSG_COLOR_SELF, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"))
        self.chat_display.tag_config("others", foreground=MSG_COLOR_OTHERS, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"))
        self.chat_display.tag_config("server", foreground=MSG_COLOR_SERVER, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"))
        self.chat_display.tag_config("buzz", foreground=BUZZ_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"))
        self.chat_display.tag_config("file", foreground=MSG_COLOR_FILE, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"))
        self.chat_display.tag_config("link", foreground=ACCENT_COLOR, underline=True)
        self.chat_display.tag_bind("link", "<Button-1>", self.click_link)
        self.chat_display.tag_bind("link", "<Enter>", lambda e: self.chat_display.config(cursor="hand2"))
        self.chat_display.tag_bind("link", "<Leave>", lambda e: self.chat_display.config(cursor=""))
        
        # NEW: Typing indicator
        self.typing_label = tk.Label(
            chat_container,
            text="",
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "italic"),
            bg=CHAT_BG_COLOR,
            fg=TEXT_SECONDARY,
            anchor="w"
        )
        self.typing_label.pack(fill="x", padx=5, pady=(0, 5))
        
        # Input area
        input_container = tk.Frame(chat_frame, bg=CHAT_BG_COLOR)
        input_container.pack(fill="x", padx=15, pady=(0, 15))
        
        # Progress bar
        self.progress_frame = tk.Frame(input_container, bg=CHAT_BG_COLOR)
        self.progress_label = tk.Label(
            self.progress_frame,
            text="",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            bg=CHAT_BG_COLOR,
            fg=TEXT_SECONDARY
        )
        self.progress_label.pack(fill="x")
        
        self.file_progress_bar = ttk.Progressbar(
            self.progress_frame,
            mode='determinate',
            length=300
        )
        self.file_progress_bar.pack(fill="x", pady=5)
        
        # Message input
        input_frame = tk.Frame(input_container, bg=INPUT_BG_COLOR, relief="flat")
        input_frame.pack(fill="x", ipady=5)
        
        plus_btn = tk.Label(
            input_frame,
            text="➕",
            font=(FONT_FAMILY, 14),
            bg=INPUT_BG_COLOR,
            fg=TEXT_SECONDARY,
            cursor="hand2",
            padx=10
        )
        plus_btn.pack(side="left")
        plus_btn.bind("<Button-1>", lambda e: self.send_file())
        
        self.message_entry = tk.Entry(
            input_frame,
            bg=INPUT_BG_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL),
            relief="flat",
            insertbackground=TEXT_COLOR
        )
        self.message_entry.pack(side="left", fill="both", expand=True, padx=5)
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        # NEW: Typing detection
        self.message_entry.bind('<KeyPress>', self.on_key_press)
        self.message_entry.bind('<KeyRelease>', self.on_key_release)
        
        send_btn = tk.Label(
            input_frame,
            text="📤",
            font=(FONT_FAMILY, 14),
            bg=INPUT_BG_COLOR,
            fg=TEXT_SECONDARY,
            cursor="hand2",
            padx=10
        )
        send_btn.pack(side="right")
        send_btn.bind("<Button-1>", lambda e: self.send_message())
    
    def create_sidebar_button(self, parent, text, command, color):
        """Create styled sidebar button."""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
            relief="flat",
            cursor="hand2",
            activebackground=color,
            activeforeground=TEXT_COLOR
        )
        btn.pack(fill="x", pady=3, ipady=8)
        
        btn.bind("<Enter>", lambda e: btn.config(bg=self.darken_color(color)))
        btn.bind("<Leave>", lambda e: btn.config(bg=color))
    
    def darken_color(self, hex_color):
        """Darken a hex color slightly."""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r, g, b = max(0, r-20), max(0, g-20), max(0, b-20)
        return f'#{r:02x}{g:02x}{b:02x}'
    
    # NEW: Typing detection methods
    def on_key_press(self, event):
        """Handle key press - start typing indicator."""
        if event.keysym in ('Return', 'Tab', 'Escape'):
            return
        
        if not self.is_typing:
            self.is_typing = True
            self.send_typing_status(True)
        
        if self.typing_timer:
            self.root.after_cancel(self.typing_timer)
        
        self.typing_timer = self.root.after(TYPING_TIMEOUT * 1000, self.stop_typing)
    
    def on_key_release(self, event):
        """Handle key release."""
        if not self.message_entry.get().strip() and self.is_typing:
            self.stop_typing()
    
    def send_typing_status(self, is_typing: bool):
        """Send typing indicator to server."""
        if not self.connected:
            return
        
        try:
            msg = create_typing_message(self.username, is_typing)
            encrypted = encrypt(msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except Exception as e:
            print(f"Typing status error: {e}")
    
    def stop_typing(self):
        """Stop typing indicator."""
        if self.is_typing:
            self.is_typing = False
            self.send_typing_status(False)
        
        if self.typing_timer:
            self.root.after_cancel(self.typing_timer)
            self.typing_timer = None
    
    def update_typing_indicator(self):
        """Update typing indicator display."""
        if not self.typing_users:
            self.typing_label.config(text="")
            return
        
        typing_list = list(self.typing_users)
        
        if len(typing_list) == 1:
            text = f"{typing_list[0]} is typing..."
        elif len(typing_list) == 2:
            text = f"{typing_list[0]} and {typing_list[1]} are typing..."
        else:
            text = f"{typing_list[0]} and {len(typing_list)-1} others are typing..."
        
        self.typing_label.config(text=text)
    
    # NEW: Status change
    def change_status(self):
        """Change user status."""
        new_status = self.status_var.get()
        
        if not self.connected:
            return
        
        try:
            msg = create_status_message(self.username, new_status)
            encrypted = encrypt(msg.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            self.my_status = new_status
        except Exception as e:
            print(f"Status change error: {e}")
    
    def connect_to_server(self):
        """Connect and authenticate."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            
            auth_msg = create_auth_message(self.username, self.password)
            encrypted = encrypt(auth_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            self.socket.settimeout(10)
            encrypted_response = self.socket.recv(BUFFER_SIZE)
            self.socket.settimeout(None)
            
            response = decrypt(encrypted_response).decode('utf-8', errors='ignore')
            parsed = parse_message(response)
            
            if parsed and parsed['type'] == MSG_TYPE_AUTH_OK:
                self.connected = True
                self.running = True
                
                self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
                self.receive_thread.start()
                
                self.display_message("SERVER", "✓ Connected to server", "server")
            else:
                error = parsed['content'] if parsed else "Authentication failed"
                messagebox.showerror("Authentication Failed", error)
                self.root.destroy()
        
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect:\n{e}")
            self.root.destroy()
    
    def receive_messages(self):
        """Receive messages thread."""
        while self.running:
            try:
                encrypted_data = self.socket.recv(BUFFER_SIZE)
                
                if not encrypted_data:
                    self.connected = False
                    self.root.after(0, self.handle_disconnection)
                    break
                
                decrypted_data = decrypt(encrypted_data)
                
                if self.receiving_file:
                    self.file_buffer += decrypted_data
                    
                    if len(self.file_buffer) >= self.expected_file_size:
                        self.handle_complete_file()
                        self.receiving_file = False
                        self.file_buffer = b''
                    else:
                        progress = (len(self.file_buffer) / self.expected_file_size) * 100
                        self.root.after(0, lambda p=progress: self.update_progress(p))
                    
                    continue
                
                try:
                    text_data = decrypted_data.decode('utf-8')
                    self.message_buffer.add_data(text_data)
                    
                    for message in self.message_buffer.get_messages():
                        self.process_message(message)
                
                except UnicodeDecodeError:
                    try:
                        text_part = decrypted_data.decode('utf-8', errors='ignore')
                        if MSG_TYPE_FILE in text_part:
                            self.message_buffer.add_data(text_part)
                            for message in self.message_buffer.get_messages():
                                self.process_message(message)
                    except:
                        pass
            
            except Exception as e:
                if self.running:
                    print(f"Receive error: {e}")
                    self.connected = False
                    self.root.after(0, self.handle_disconnection)
                break
    
    def process_message(self, raw_message: str):
        """Process received message."""
        parsed = parse_message(raw_message)
        
        if not parsed:
            return
        
        msg_type = parsed['type']
        sender = parsed['sender']
        content = parsed['content']
        
        if msg_type == MSG_TYPE_TEXT:
            tag = "self" if sender == self.username else "others"
            self.root.after(0, lambda: self.display_message(sender, content, tag))
        
        # NEW: Typing indicators
        elif msg_type == MSG_TYPE_TYPING_START or msg_type == 'TYPING_START':
            self.typing_users.add(sender)
            self.root.after(0, self.update_typing_indicator)
        
        elif msg_type == MSG_TYPE_TYPING_STOP or msg_type == 'TYPING_STOP':
            self.typing_users.discard(sender)
            self.root.after(0, self.update_typing_indicator)
        
        # NEW: Status changes
        elif msg_type == MSG_TYPE_STATUS_CHANGE or msg_type == 'STATUS_CHANGE':
            self.user_statuses[sender] = content
            self.root.after(0, self.refresh_user_list)
        
        # NEW: Session ID
        elif msg_type == MSG_TYPE_SESSION_ID or msg_type == 'SESSION_ID':
            self.session_id = content
        
        elif msg_type == MSG_TYPE_USER_JOIN:
            self.root.after(0, lambda: self.display_message("SERVER", f"→ {content} joined", "server"))
        
        elif msg_type == MSG_TYPE_USER_LEAVE:
            self.typing_users.discard(content)
            self.root.after(0, lambda: self.display_message("SERVER", f"← {content} left", "server"))
            self.root.after(0, self.update_typing_indicator)
        
        elif msg_type == MSG_TYPE_USER_LIST:
            users = json.loads(content)
            self.root.after(0, lambda: self.update_user_list(users))
        
        elif msg_type == MSG_TYPE_BUZZ:
            self.root.after(0, lambda: self.handle_buzz(sender))
        
        elif msg_type == MSG_TYPE_FILE:
            self.root.after(0, lambda: self.handle_file_start(sender, content))
        
        elif msg_type == MSG_TYPE_FILE_COMPLETE:
            parts = content.split('|')
            filename = parts[0] if parts else "unknown"
            self.root.after(0, lambda: self.display_message(
                "SERVER",
                f"✓ File transfer complete: {filename}",
                "file"
            ))
        
        elif msg_type == MSG_TYPE_ERROR:
            self.root.after(0, lambda: self.display_message("ERROR", content, "buzz"))
    
    def send_message(self):
        """Send text message."""
        text = self.message_entry.get().strip()
        
        if not text or not self.connected:
            return
        
        # Stop typing indicator
        self.stop_typing()
        
        try:
            message = create_text_message(self.username, text)
            encrypted = encrypt(message.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            self.message_entry.delete(0, tk.END)
            self.display_message(self.username, text, "self")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send:\n{e}")
    
    def send_buzz(self):
        """Send buzz."""
        if not self.connected:
            return
        
        try:
            message = create_buzz_message(self.username)
            encrypted = encrypt(message.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            self.display_message("YOU", "Sent a BUZZ! ⚡", "buzz")
        except Exception as e:
            print(f"Buzz error: {e}")
    
    def send_file(self):
        """Send file in background thread."""
        if not self.connected:
            return
        
        filepath = filedialog.askopenfilename(title="Select file")
        
        if not filepath:
            return
        
        is_valid, error = validate_file(filepath)
        if not is_valid:
            messagebox.showerror("Invalid File", error)
            self.send_file_thread = threading.Thread(
            target=self._send_file_worker,
            args=(filepath,),
            daemon=True
        )
        self.send_file_thread.start()

    def _send_file_worker(self, filepath: str):
        """Worker thread for sending file."""
        try:
            file_info = get_file_info(filepath)
            
            self.root.after(0, lambda: self.display_message(
                "YOU",
                f"📤 Sending: {file_info['filename']} ({format_file_size(file_info['filesize'])})",
                "file"
            ))
            
            file_msg = create_file_message(self.username, file_info['filename'], file_info['filesize'])
            encrypted = encrypt(file_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            time.sleep(0.2)
            
            if file_info['is_large']:
                self.root.after(0, lambda: self.show_progress(f"Uploading {file_info['filename']}"))
            
            def progress_callback(current, total):
                percent = (current / total) * 100
                self.root.after(0, lambda p=percent: self.update_progress(p))
            
            with FileReader(filepath, progress_callback=progress_callback) as reader:
                while True:
                    chunk = reader.read_chunk()
                    
                    if not chunk:
                        break
                    
                    encrypted_chunk = encrypt(chunk)
                    self.socket.sendall(encrypted_chunk)
                    time.sleep(0.01)
            
            complete_msg = create_message(
                MSG_TYPE_FILE_COMPLETE,
                self.username,
                f"{file_info['filename']}|{file_info['hash']}"
            )
            encrypted = encrypt(complete_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            if file_info['is_large']:
                self.root.after(0, self.hide_progress)
            
            self.root.after(0, lambda: self.display_message(
                "YOU",
                f"✓ File sent successfully",
                "file"
            ))
        
        except Exception as e:
            self.root.after(0, self.hide_progress)
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to send file:\n{e}"))
            print(f"File send error: {e}")

    def handle_file_start(self, sender: str, content: str):
        """Handle file transfer start."""
        try:
            parts = content.split('|')
            filename = parts[0]
            filesize = int(parts[1])
            
            self.display_message(
                sender,
                f"📥 Receiving: {filename} ({format_file_size(filesize)})",
                "file"
            )
            
            def progress_callback(current, total):
                percent = (current / total) * 100
                self.root.after(0, lambda p=percent: self.update_progress(p))
            
            self.active_file_writer = FileWriter(filename, filesize, progress_callback)
            self.active_file_writer.open()
            
            self.receiving_file = True
            self.expected_file_size = filesize
            self.current_filename = filename
            self.file_buffer = b''
            
            if filesize > LARGE_FILE_THRESHOLD:
                self.show_progress(f"Downloading {filename}")
        
        except Exception as e:
            print(f"File start error: {e}")

    def handle_complete_file(self):
        """Handle complete file reception."""
        try:
            if self.active_file_writer:
                self.active_file_writer.write_chunk(self.file_buffer)
                filepath = self.active_file_writer.get_filepath()
                self.active_file_writer.close()
                self.active_file_writer = None
                
                self.hide_progress()
                self.display_file_received(filepath)
        
        except Exception as e:
            print(f"Complete file error: {e}")

    def display_file_received(self, filepath: str):
        """Display received file with clickable path."""
        self.chat_display.config(state="normal")
        
        timestamp = datetime.now().strftime("%H:%M")
        filename = os.path.basename(filepath)
        
        self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.chat_display.insert(tk.END, "FILE RECEIVED", "file")
        self.chat_display.insert(tk.END, f": {filename}\n")
        self.chat_display.insert(tk.END, f"  📂 ", "timestamp")
        
        link_start = self.chat_display.index(tk.END + "-1c")
        self.chat_display.insert(tk.END, filepath, "link")
        link_end = self.chat_display.index(tk.END + "-1c")
        
        self.chat_display.tag_add(f"path:{filepath}", link_start, link_end)
        
        self.chat_display.insert(tk.END, "\n")
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state="disabled")

    def click_link(self, event):
        """Handle link click."""
        try:
            index = self.chat_display.index(f"@{event.x},{event.y}")
            tags = self.chat_display.tag_names(index)
            
            for tag in tags:
                if tag.startswith("path:"):
                    filepath = tag[5:]
                    open_file_location(filepath)
                    break
        except:
            pass

    def show_progress(self, text: str):
        """Show progress bar."""
        self.progress_label.config(text=text)
        self.progress_frame.pack(fill="x", pady=(0, 5))
        self.file_progress_bar['value'] = 0

    def update_progress(self, percent: float):
        """Update progress bar."""
        self.file_progress_bar['value'] = percent
        self.progress_label.config(text=f"Progress: {percent:.1f}%")

    def hide_progress(self):
        """Hide progress bar."""
        self.progress_frame.pack_forget()
        self.file_progress_bar['value'] = 0

    def handle_buzz(self, sender: str):
        """Handle buzz with window shake."""
        self.display_message(sender, "💥 BUZZ!", "buzz")
        
        original_x = self.root.winfo_x()
        original_y = self.root.winfo_y()
        
        def shake_step(count):
            if count <= 0:
                self.root.geometry(f"+{original_x}+{original_y}")
                return
            
            offset_x = BUZZ_SHAKE_DISTANCE if count % 2 == 0 else -BUZZ_SHAKE_DISTANCE
            offset_y = BUZZ_SHAKE_DISTANCE if count % 2 == 0 else -BUZZ_SHAKE_DISTANCE
            
            self.root.geometry(f"+{original_x + offset_x}+{original_y + offset_y}")
            self.root.after(BUZZ_SHAKE_INTERVAL, lambda: shake_step(count - 1))
        
        shake_step(10)

    def display_message(self, sender: str, text: str, tag: str):
        """Display message with enhanced timestamp."""
        self.chat_display.config(state="normal")
        
        now = datetime.now()
        
        if hasattr(self, 'last_message_date') and self.last_message_date:
            if self.last_message_date != now.date():
                date_text = f"\n───── {now.strftime('%B %d, %Y')} ─────\n"
                self.chat_display.insert(tk.END, date_text, "timestamp")
        
        self.last_message_date = now.date()
        
        timestamp = now.strftime("%H:%M")
        
        self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.chat_display.insert(tk.END, f"{sender}: ", tag)
        self.chat_display.insert(tk.END, f"{text}\n")
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state="disabled")

    def update_user_list(self, users_data):
        """Update user list with status indicators."""
        self.users_listbox.delete(0, tk.END)
        
        if users_data and isinstance(users_data[0], str):
            users_data = [{'username': u, 'status': STATUS_ONLINE, 'typing': False} 
                        for u in users_data]
        
        for user_info in sorted(users_data, key=lambda x: x['username']):
            username = user_info['username']
            status = user_info.get('status', STATUS_ONLINE)
            is_typing = user_info.get('typing', False)
            
            if status == STATUS_ONLINE:
                status_icon = "🟢"
            elif status == STATUS_BUSY:
                status_icon = "🔴"
            else:
                status_icon = "⚫"
            
            if username == self.username:
                display = f"→ {status_icon} {username}"
            else:
                display = f"  {status_icon} {username}"
            
            if is_typing:
                display += " ✏️"
            
            self.users_listbox.insert(tk.END, display)

    def refresh_user_list(self):
        """Refresh user list display."""
        pass

    # NEW: Reconnect handling
    def handle_disconnection(self):
        """Handle server disconnection."""
        self.display_message("SERVER", "⚠ Connection lost", "buzz")
        self.show_reconnect_button()

    def show_reconnect_button(self):
        """Display reconnect button."""
        if not hasattr(self, 'reconnect_frame'):
            self.reconnect_frame = tk.Frame(self.root, bg=BG_COLOR)
        
        self.reconnect_frame.pack(side="bottom", fill="x", pady=5)
        
        tk.Label(
            self.reconnect_frame,
            text="⚠ Disconnected from server",
            bg=BG_COLOR,
            fg=ERROR_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold")
        ).pack(side="left", padx=10)
        
        reconnect_btn = tk.Button(
            self.reconnect_frame,
            text="🔄 Reconnect",
            command=self.attempt_reconnect,
            bg=ACCENT_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
            relief="flat",
            cursor="hand2"
        )
        reconnect_btn.pack(side="left", padx=5)

    def attempt_reconnect(self):
        """Attempt to reconnect to server."""
        self.display_message("SYSTEM", "Attempting to reconnect...", "server")
        
        try:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.server_ip, self.server_port))
            self.socket.settimeout(None)
            
            auth_msg = create_auth_message(self.username, self.password)
            encrypted = encrypt(auth_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            self.socket.settimeout(10)
            encrypted_response = self.socket.recv(BUFFER_SIZE)
            self.socket.settimeout(None)
            
            response = decrypt(encrypted_response).decode('utf-8', errors='ignore')
            parsed = parse_message(response)
            
            if parsed and parsed['type'] == MSG_TYPE_AUTH_OK:
                self.connected = True
                
                self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
                self.receive_thread.start()
                
                if hasattr(self, 'reconnect_frame'):
                    self.reconnect_frame.pack_forget()
                
                self.display_message("SYSTEM", "✓ Reconnected successfully!", "server")
            else:
                raise Exception("Authentication failed on reconnect")
        
        except Exception as e:
            self.display_message("SYSTEM", f"✗ Reconnect failed: {e}", "buzz")
            messagebox.showerror("Reconnect Failed", f"Could not reconnect:\n{e}")

    def on_closing(self):
        """Handle close."""
        if messagebox.askokcancel("Quit", "Exit chat?"):
            self.running = False
            self.stop_typing()
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            self.root.destroy()

    def run(self):
        """Start GUI."""
        self.root.mainloop()

def main():
    """Entry point."""
    app = ChatClient()
    app.run()

if __name__ == "__main__":
    main()