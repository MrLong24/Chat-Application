import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import socket
import threading
import sys
import os
from datetime import datetime
import time
import json
import uuid
import queue
import base64

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import *
from common.protocol import *
from common.encryption import encrypt, decrypt
from common.file_handler import (
    validate_file, get_file_info, FileReader, FileWriter,
    format_file_size, open_file_location
)


# ==================== FILE TRANSFER MANAGER ====================

class FileTransferManager:
    """
    Manages multiple concurrent file transfers.
    Each transfer runs in a dedicated thread.
    """
    
    def __init__(self, client_socket, username, ui_queue):
        self.socket = client_socket
        self.username = username
        self.ui_queue = ui_queue  # Thread-safe queue for UI updates
        
        # Active transfers: {file_id: FileTransfer object}
        self.transfers = {}
        self.transfers_lock = threading.Lock()
    
    def create_send_transfer(self, filepath: str) -> str:
        """
        Create a new outgoing file transfer.
        
        Returns:
            str: file_id if successful, None otherwise
        """
        # Validate file
        is_valid, error = validate_file(filepath)
        if not is_valid:
            self.ui_queue.put(('error', f"Invalid file: {error}"))
            return None
        
        # Get file info
        file_info = get_file_info(filepath)
        file_id = str(uuid.uuid4())
        
        # Create transfer object
        transfer = FileSendTransfer(
            file_id=file_id,
            filepath=filepath,
            filename=file_info['filename'],
            filesize=file_info['filesize'],
            socket=self.socket,
            username=self.username,
            ui_queue=self.ui_queue
        )
        
        with self.transfers_lock:
            self.transfers[file_id] = transfer
        
        # Send FILE_OFFER
        offer_msg = create_file_offer_message(
            self.username,
            file_id,
            file_info['filename'],
            file_info['filesize'],
            file_info['hash']
        )
        
        try:
            encrypted = encrypt(offer_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            # Update UI
            self.ui_queue.put(('send_offer', {
                'file_id': file_id,
                'filename': file_info['filename'],
                'filesize': file_info['filesize'],
                'state': FILE_STATE_OFFERED
            }))
            
            return file_id
        except Exception as e:
            self.ui_queue.put(('error', f"Failed to send offer: {e}"))
            return None
    
    def create_receive_transfer(self, file_id: str, sender: str, filename: str, filesize: int):
        """Create a new incoming file transfer (waiting for user action)."""
        with self.transfers_lock:
            if file_id not in self.transfers:
                transfer = FileReceiveTransfer(
                    file_id=file_id,
                    sender=sender,
                    filename=filename,
                    filesize=filesize,
                    socket=self.socket,
                    username=self.username,
                    ui_queue=self.ui_queue
                )
                self.transfers[file_id] = transfer
        
        # Update UI - show incoming file
        self.ui_queue.put(('receive_offer', {
            'file_id': file_id,
            'sender': sender,
            'filename': filename,
            'filesize': filesize,
            'state': FILE_STATE_OFFERED
        }))
    
    def accept_transfer(self, file_id: str):
        """Accept an incoming file transfer."""
        with self.transfers_lock:
            if file_id in self.transfers:
                transfer = self.transfers[file_id]
                if isinstance(transfer, FileReceiveTransfer):
                    transfer.accept()
    
    def reject_transfer(self, file_id: str, reason: str = "User declined"):
        """Reject an incoming file transfer."""
        with self.transfers_lock:
            if file_id in self.transfers:
                transfer = self.transfers[file_id]
                if isinstance(transfer, FileReceiveTransfer):
                    transfer.reject(reason)
                    del self.transfers[file_id]
    
    def pause_transfer(self, file_id: str):
        """Pause a transfer."""
        with self.transfers_lock:
            if file_id in self.transfers:
                self.transfers[file_id].pause()
    
    def resume_transfer(self, file_id: str):
        """Resume a paused transfer."""
        with self.transfers_lock:
            if file_id in self.transfers:
                self.transfers[file_id].resume()
    
    def cancel_transfer(self, file_id: str):
        """Cancel a transfer."""
        with self.transfers_lock:
            if file_id in self.transfers:
                self.transfers[file_id].cancel()
                del self.transfers[file_id]
    
    def handle_accept(self, file_id: str):
        """Handle FILE_ACCEPT from receiver."""
        with self.transfers_lock:
            if file_id in self.transfers:
                transfer = self.transfers[file_id]
                if isinstance(transfer, FileSendTransfer):
                    transfer.start_sending()
    
    def handle_data_chunk(self, file_id: str, offset: int, chunk_data: bytes):
        """Handle incoming FILE_DATA chunk (ALREADY Base64-decoded)."""
        with self.transfers_lock:
            if file_id in self.transfers:
                transfer = self.transfers[file_id]
                if isinstance(transfer, FileReceiveTransfer):
                    transfer.write_chunk(offset, chunk_data)
    
    def handle_pause(self, file_id: str, offset: int):
        """Handle FILE_PAUSE from other party."""
        with self.transfers_lock:
            if file_id in self.transfers:
                self.transfers[file_id].remote_pause(offset)
    
    def handle_resume(self, file_id: str, offset: int):
        """Handle FILE_RESUME from other party."""
        with self.transfers_lock:
            if file_id in self.transfers:
                self.transfers[file_id].remote_resume(offset)
    
    def handle_cancel(self, file_id: str):
        """Handle FILE_CANCEL from other party."""
        with self.transfers_lock:
            if file_id in self.transfers:
                self.transfers[file_id].remote_cancel()
                del self.transfers[file_id]
    
    def handle_complete(self, file_id: str):
        """Handle FILE_COMPLETE."""
        with self.transfers_lock:
            if file_id in self.transfers:
                self.transfers[file_id].complete()


class FileSendTransfer:
    """Handles sending a single file with Base64 encoding."""
    
    def __init__(self, file_id, filepath, filename, filesize, socket, username, ui_queue):
        self.file_id = file_id
        self.filepath = filepath
        self.filename = filename
        self.filesize = filesize
        self.socket = socket
        self.username = username
        self.ui_queue = ui_queue
        
        self.state = FILE_STATE_OFFERED
        self.offset = 0
        self.paused = False
        self.cancelled = False
        
        self.send_thread = None
        self.lock = threading.Lock()
    
    def start_sending(self):
        """Start sending file in background thread."""
        with self.lock:
            if self.state == FILE_STATE_OFFERED:
                self.state = FILE_STATE_TRANSFERRING
                self.send_thread = threading.Thread(target=self._send_worker, daemon=True)
                self.send_thread.start()
    
    def _send_worker(self):
        """Worker thread for sending file with Base64 encoding."""
        try:
            with FileReader(self.filepath) as reader:
                while not self.cancelled:
                    # Check if paused
                    with self.lock:
                        if self.paused:
                            time.sleep(0.1)
                            continue
                    
                    # Read binary chunk
                    chunk = reader.read_chunk()
                    if not chunk:
                        break
                    
                    # Create Base64-encoded FILE_DATA message (NOW RETURNS STRING)
                    data_msg = create_file_data_message(
                        self.username,
                        self.file_id,
                        self.offset,
                        chunk  # Binary bytes - will be Base64-encoded inside
                    )
                    
                    # Send as TEXT through normal pipeline
                    encrypted = encrypt(data_msg.encode('utf-8'))
                    self.socket.sendall(encrypted)
                    
                    self.offset += len(chunk)
                    
                    # Update UI
                    progress = (self.offset / self.filesize) * 100
                    self.ui_queue.put(('send_progress', {
                        'file_id': self.file_id,
                        'offset': self.offset,
                        'progress': progress
                    }))
                    
                    time.sleep(0.01)  # Small delay to avoid flooding
            
            # Send FILE_COMPLETE
            if not self.cancelled:
                complete_msg = create_file_complete_message_v2(self.username, self.file_id)
                encrypted = encrypt(complete_msg.encode('utf-8'))
                self.socket.sendall(encrypted)
                
                with self.lock:
                    self.state = FILE_STATE_COMPLETED
                
                self.ui_queue.put(('send_complete', {'file_id': self.file_id}))
        
        except Exception as e:
            self.ui_queue.put(('error', f"Send error: {e}"))
            with self.lock:
                self.state = FILE_STATE_ERROR
    
    def pause(self):
        """Pause sending."""
        with self.lock:
            if self.state == FILE_STATE_TRANSFERRING:
                self.paused = True
                self.state = FILE_STATE_PAUSED
        
        # Send FILE_PAUSE
        pause_msg = create_file_pause_message(self.username, self.file_id, self.offset)
        try:
            encrypted = encrypt(pause_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except:
            pass
        
        self.ui_queue.put(('send_paused', {'file_id': self.file_id}))
    
    def resume(self):
        """Resume sending."""
        with self.lock:
            if self.state == FILE_STATE_PAUSED:
                self.paused = False
                self.state = FILE_STATE_TRANSFERRING
        
        # Send FILE_RESUME
        resume_msg = create_file_resume_message(self.username, self.file_id, self.offset)
        try:
            encrypted = encrypt(resume_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except:
            pass
        
        self.ui_queue.put(('send_resumed', {'file_id': self.file_id}))
    
    def cancel(self):
        """Cancel sending."""
        with self.lock:
            self.cancelled = True
            self.state = FILE_STATE_CANCELLED
        
        # Send FILE_CANCEL
        cancel_msg = create_file_cancel_message(self.username, self.file_id, "User cancelled")
        try:
            encrypted = encrypt(cancel_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except:
            pass
        
        self.ui_queue.put(('send_cancelled', {'file_id': self.file_id}))
    
    def remote_pause(self, offset):
        """Handle pause request from receiver."""
        with self.lock:
            self.paused = True
            self.state = FILE_STATE_PAUSED
        self.ui_queue.put(('send_paused', {'file_id': self.file_id}))
    
    def remote_resume(self, offset):
        """Handle resume request from receiver."""
        with self.lock:
            self.paused = False
            self.state = FILE_STATE_TRANSFERRING
        self.ui_queue.put(('send_resumed', {'file_id': self.file_id}))
    
    def remote_cancel(self):
        """Handle cancel from receiver."""
        with self.lock:
            self.cancelled = True
            self.state = FILE_STATE_CANCELLED
        self.ui_queue.put(('send_cancelled', {'file_id': self.file_id}))
    
    def complete(self):
        """Mark as completed."""
        with self.lock:
            self.state = FILE_STATE_COMPLETED


class FileReceiveTransfer:
    """Handles receiving a single file with Base64 decoding."""
    
    def __init__(self, file_id, sender, filename, filesize, socket, username, ui_queue):
        self.file_id = file_id
        self.sender = sender
        self.filename = filename
        self.filesize = filesize
        self.socket = socket
        self.username = username
        self.ui_queue = ui_queue

        self.state = FILE_STATE_OFFERED
        self.offset = 0
        self.lock = threading.Lock()

        # Create download directory and file
        download_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(download_dir, exist_ok=True)
        self.file_path = os.path.join(download_dir, filename)

        # Create empty file with full size
        with open(self.file_path, 'wb') as f:
            f.truncate(self.filesize)

    
    def accept(self):
        """Accept the file transfer."""
        with self.lock:
            if self.state != FILE_STATE_OFFERED:
                return
            self.state = FILE_STATE_ACCEPTED

        accept_msg = create_file_accept_message(self.username, self.file_id)
        encrypted = encrypt(accept_msg.encode('utf-8'))
        self.socket.sendall(encrypted)

        self.ui_queue.put(('receive_accepted', {'file_id': self.file_id}))

    def reject(self, reason: str):
        """Reject the file transfer."""
        with self.lock:
            self.state = FILE_STATE_REJECTED
        
        # Send FILE_REJECT
        reject_msg = create_file_reject_message(self.username, self.file_id, reason)
        try:
            encrypted = encrypt(reject_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except:
            pass
        
        self.ui_queue.put(('receive_rejected', {'file_id': self.file_id}))
    
    def write_chunk(self, offset: int, chunk_data: bytes):
        """
        Write received chunk to file.
        
        Args:
            offset: Byte offset in file
            chunk_data: ALREADY Base64-DECODED binary data
        """
        if not chunk_data:
            return

        with self.lock:
            if self.state not in [FILE_STATE_ACCEPTED, FILE_STATE_TRANSFERRING]:
                return

            self.state = FILE_STATE_TRANSFERRING

            # Write to file at correct offset
            with open(self.file_path, 'rb+') as f:
                f.seek(offset)
                f.write(chunk_data)

            # Update progress
            self.offset = max(self.offset, offset + len(chunk_data))

            progress = (self.offset / self.filesize) * 100
            self.ui_queue.put(('receive_progress', {
                'file_id': self.file_id,
                'offset': self.offset,
                'progress': progress
            }))
    
    def pause(self):
        """Pause receiving."""
        with self.lock:
            self.state = FILE_STATE_PAUSED
        
        pause_msg = create_file_pause_message(self.username, self.file_id, self.offset)
        try:
            encrypted = encrypt(pause_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except:
            pass
        
        self.ui_queue.put(('receive_paused', {'file_id': self.file_id}))
    
    def resume(self):
        """Resume receiving."""
        with self.lock:
            self.state = FILE_STATE_TRANSFERRING
        
        resume_msg = create_file_resume_message(self.username, self.file_id, self.offset)
        try:
            encrypted = encrypt(resume_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except:
            pass
        
        self.ui_queue.put(('receive_resumed', {'file_id': self.file_id}))
    
    def cancel(self):
        """Cancel receiving."""
        with self.lock:
            self.state = FILE_STATE_CANCELLED
        
        cancel_msg = create_file_cancel_message(self.username, self.file_id, "User cancelled")
        try:
            encrypted = encrypt(cancel_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except:
            pass
        
        self.ui_queue.put(('receive_cancelled', {'file_id': self.file_id}))
    
    def remote_pause(self, offset):
        """Handle pause from sender."""
        with self.lock:
            self.state = FILE_STATE_PAUSED
        self.ui_queue.put(('receive_paused', {'file_id': self.file_id}))
    
    def remote_resume(self, offset):
        """Handle resume from sender."""
        with self.lock:
            self.state = FILE_STATE_TRANSFERRING
        self.ui_queue.put(('receive_resumed', {'file_id': self.file_id}))
    
    def remote_cancel(self):
        """Handle cancel from sender."""
        with self.lock:
            self.state = FILE_STATE_CANCELLED
        self.ui_queue.put(('receive_cancelled', {'file_id': self.file_id}))
    
    def complete(self):
        """Mark as completed."""
        with self.lock:
            self.state = FILE_STATE_COMPLETED

        self.ui_queue.put(('receive_complete', {
            'file_id': self.file_id,
            'filepath': self.file_path
        }))


# Continue in Part 2...


# ==================== FILE TRANSFER UI PANEL ====================

class FileTransferPanel:
    """UI panel for displaying file transfers."""
    
    def __init__(self, parent, transfer_manager):
        self.parent = parent
        self.transfer_manager = transfer_manager
        
        # Transfer widgets: {file_id: widget_dict}
        self.transfer_widgets = {}
        
        self.create_ui()
    
    def create_ui(self):
        """Create file transfer panel UI."""
        # Main frame
        self.panel = tk.Frame(self.parent, bg=SIDEBAR_COLOR)
        
        # Header
        header = tk.Label(
            self.panel,
            text="FILE TRANSFERS",
            font=(FONT_FAMILY, FONT_SIZE_SMALL, "bold"),
            bg=SIDEBAR_COLOR,
            fg=TEXT_SECONDARY,
            pady=10
        )
        header.pack(fill="x", padx=10)
        
        ttk.Separator(self.panel, orient='horizontal').pack(fill='x', padx=10)
        
        # Scrollable container
        canvas = tk.Canvas(self.panel, bg=SIDEBAR_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.panel, orient="vertical", command=canvas.yview)
        
        self.transfer_container = tk.Frame(canvas, bg=SIDEBAR_COLOR)
        
        self.transfer_container.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.transfer_container, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y")
    
    def show(self):
        """Show the panel."""
        self.panel.pack(side="right", fill="both", expand=False, ipadx=200)
    
    def hide(self):
        """Hide the panel."""
        self.panel.pack_forget()
    
    def add_send_transfer(self, file_id, filename, filesize):
        """Add a sending transfer to UI."""
        frame = tk.Frame(self.transfer_container, bg=INPUT_BG_COLOR, relief="raised", bd=1)
        frame.pack(fill="x", padx=5, pady=5)
        
        # Header
        header_frame = tk.Frame(frame, bg=INPUT_BG_COLOR)
        header_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(
            header_frame,
            text="📤 " + filename,
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
            bg=INPUT_BG_COLOR,
            fg=TEXT_COLOR,
            anchor="w"
        ).pack(side="left", fill="x", expand=True)
        
        # Size
        tk.Label(
            frame,
            text=f"Size: {format_file_size(filesize)}",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            bg=INPUT_BG_COLOR,
            fg=TEXT_SECONDARY,
            anchor="w"
        ).pack(fill="x", padx=10)
        
        # Progress bar
        progress = ttk.Progressbar(frame, mode='determinate', length=200)
        progress.pack(fill="x", padx=10, pady=5)
        
        # Status
        status_label = tk.Label(
            frame,
            text="Waiting for response...",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            bg=INPUT_BG_COLOR,
            fg=WARNING_COLOR
        )
        status_label.pack(fill="x", padx=10)
        
        # Controls
        btn_frame = tk.Frame(frame, bg=INPUT_BG_COLOR)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        pause_btn = tk.Button(
            btn_frame,
            text="⏸ Pause",
            command=lambda: self.transfer_manager.pause_transfer(file_id),
            bg=WARNING_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            relief="flat",
            state="disabled"
        )
        pause_btn.pack(side="left", padx=2)
        
        cancel_btn = tk.Button(
            btn_frame,
            text="❌ Cancel",
            command=lambda: self.transfer_manager.cancel_transfer(file_id),
            bg=ERROR_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            relief="flat"
        )
        cancel_btn.pack(side="left", padx=2)
        
        self.transfer_widgets[file_id] = {
            'frame': frame,
            'progress': progress,
            'status': status_label,
            'pause_btn': pause_btn,
            'cancel_btn': cancel_btn,
            'type': 'send'
        }
    
    def add_receive_transfer(self, file_id, sender, filename, filesize):
        """Add a receiving transfer to UI."""
        frame = tk.Frame(self.transfer_container, bg=INPUT_BG_COLOR, relief="raised", bd=1)
        frame.pack(fill="x", padx=5, pady=5)
        
        # Header
        header_frame = tk.Frame(frame, bg=INPUT_BG_COLOR)
        header_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(
            header_frame,
            text=f"📥 {filename}",
            font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
            bg=INPUT_BG_COLOR,
            fg=TEXT_COLOR,
            anchor="w"
        ).pack(side="left", fill="x", expand=True)
        
        # Sender + Size
        tk.Label(
            frame,
            text=f"From: {sender} • {format_file_size(filesize)}",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            bg=INPUT_BG_COLOR,
            fg=TEXT_SECONDARY,
            anchor="w"
        ).pack(fill="x", padx=10)
        
        # Progress bar (hidden initially)
        progress = ttk.Progressbar(frame, mode='determinate', length=200)
        
        # Status
        status_label = tk.Label(
            frame,
            text="Waiting for your action...",
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            bg=INPUT_BG_COLOR,
            fg=WARNING_COLOR
        )
        status_label.pack(fill="x", padx=10)
        
        # Controls
        btn_frame = tk.Frame(frame, bg=INPUT_BG_COLOR)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        accept_btn = tk.Button(
            btn_frame,
            text="✓ Download",
            command=lambda: self._accept_download(file_id),
            bg=SUCCESS_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            relief="flat"
        )
        accept_btn.pack(side="left", padx=2)
        
        reject_btn = tk.Button(
            btn_frame,
            text="✗ Reject",
            command=lambda: self._reject_download(file_id),
            bg=ERROR_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            relief="flat"
        )
        reject_btn.pack(side="left", padx=2)
        
        pause_btn = tk.Button(
            btn_frame,
            text="⏸ Pause",
            command=lambda: self.transfer_manager.pause_transfer(file_id),
            bg=WARNING_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, FONT_SIZE_SMALL),
            relief="flat",
            state="disabled"
        )
        
        self.transfer_widgets[file_id] = {
            'frame': frame,
            'progress': progress,
            'status': status_label,
            'accept_btn': accept_btn,
            'reject_btn': reject_btn,
            'pause_btn': pause_btn,
            'type': 'receive'
        }
    
    def _accept_download(self, file_id):
        """Handle download button click."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            # Hide accept/reject buttons
            widgets['accept_btn'].pack_forget()
            widgets['reject_btn'].pack_forget()
            
            # Show progress bar
            widgets['progress'].pack(fill="x", padx=10, pady=5, before=widgets['status'])
            
            # Show pause button
            widgets['pause_btn'].pack(side="left", padx=2)
            widgets['pause_btn'].config(state="normal")
            
            # Update status
            widgets['status'].config(text="Downloading...", fg=SUCCESS_COLOR)
            
            # Start download
            self.transfer_manager.accept_transfer(file_id)
    
    def _reject_download(self, file_id):
        """Handle reject button click."""
        self.transfer_manager.reject_transfer(file_id)
        self.remove_transfer(file_id)
    
    def update_progress(self, file_id, progress):
        """Update progress bar."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            widgets['progress']['value'] = progress
            widgets['status'].config(text=f"Progress: {progress:.1f}%")
    
    def set_status(self, file_id, status_text, color=TEXT_COLOR):
        """Update status text."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            widgets['status'].config(text=status_text, fg=color)
    
    def mark_paused(self, file_id):
        """Mark transfer as paused."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            widgets['status'].config(text="Paused", fg=WARNING_COLOR)
            widgets['pause_btn'].config(text="▶ Resume", 
                command=lambda: self.transfer_manager.resume_transfer(file_id))
    
    def mark_resumed(self, file_id):
        """Mark transfer as resumed."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            if widgets['type'] == 'send':
                widgets['status'].config(text="Sending...", fg=SUCCESS_COLOR)
            else:
                widgets['status'].config(text="Downloading...", fg=SUCCESS_COLOR)
            widgets['pause_btn'].config(text="⏸ Pause",
                command=lambda: self.transfer_manager.pause_transfer(file_id))
    
    def mark_completed(self, file_id):
        """Mark transfer as completed."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            widgets['progress']['value'] = 100
            widgets['status'].config(text="✓ Completed", fg=SUCCESS_COLOR)
            widgets['pause_btn'].config(state="disabled")
            if 'cancel_btn' in widgets:
                widgets['cancel_btn'].config(state="disabled")
    
    def mark_cancelled(self, file_id):
        """Mark transfer as cancelled."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            widgets['status'].config(text="✗ Cancelled", fg=ERROR_COLOR)
    
    def remove_transfer(self, file_id):
        """Remove transfer from UI."""
        widgets = self.transfer_widgets.get(file_id)
        if widgets:
            widgets['frame'].destroy()
            del self.transfer_widgets[file_id]


# ==================== LOGIN DIALOG ====================

class LoginDialog:
    """Discord-themed login dialog."""
    
    def __init__(self, parent):
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Login - Chat Application")
        self.dialog.geometry("450x520")
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=BG_COLOR)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - 225
        y = (self.dialog.winfo_screenheight() // 2) - 260
        self.dialog.geometry(f"450x520+{x}+{y}")
        
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
    """Main chat client with Tier 2 file transfer support."""
    
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
        self.password = None
        
        # Message buffer
        self.message_buffer = MessageBuffer()
        
        # TIER 2: File transfer manager
        self.ui_queue = queue.Queue()  # Thread-safe queue for UI updates
        self.file_transfer_manager = None
        self.file_transfer_panel = None
        
        # Tier 1: Typing and status
        self.typing_timer = None
        self.is_typing = False
        self.typing_users = set()
        self.user_statuses = {}
        self.session_id = None
        self.my_status = STATUS_ONLINE
        self.last_message_date = None
        
        # Tier 1: Message tracking
        self.received_message_ids = []
        self.sent_message_ids = {}
        
        # Threading
        self.receive_thread = None
        self.running = False
        
        # Show login
        if not self.show_login():
            self.root.destroy()
            return
        
        # Create GUI
        self.create_widgets()
        
        # Initialize file transfer manager AFTER socket connected
        # Connect
        self.connect_to_server()
        
        # Start UI queue processor
        self.process_ui_queue()
        
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
        
        # Status selector
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
        
        # TIER 2: File transfer toggle button
        self.create_sidebar_button(btn_frame, "📋 Transfers", self.toggle_file_panel, MSG_COLOR_FILE)
        
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
        
        # Typing indicator
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
        
        emoji_btn = tk.Label(
            input_frame,
            text="😀",
            font=(FONT_FAMILY, 14),
            bg=INPUT_BG_COLOR,
            fg=TEXT_SECONDARY,
            cursor="hand2",
            padx=10
        )
        emoji_btn.pack(side="left")
        emoji_btn.bind("<Button-1>", lambda e: self.open_emoji_picker())
        
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
        
        # TIER 2: Create file transfer panel (hidden by default)
        self.file_transfer_panel = FileTransferPanel(main_frame, None)  # Will set manager after connection
    
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
    
    def toggle_file_panel(self):
        """Toggle file transfer panel visibility."""
        if hasattr(self.file_transfer_panel.panel, 'winfo_ismapped') and self.file_transfer_panel.panel.winfo_ismapped():
            self.file_transfer_panel.hide()
        else:
            self.file_transfer_panel.show()
    
    def open_emoji_picker(self):
        """Open emoji picker window."""
        picker = tk.Toplevel(self.root)
        picker.title("Emojis")
        picker.geometry("400x400")
        picker.transient(self.root)
        picker.grab_set()
        
        emojis = [
            "😀", "😁", "😂", "🤣", "😃", "😄", "😅", "😆", "😉", "😊",
            "😋", "😎", "😍", "😘", "🥰", "😗", "😙", "😚", "🙂", "🤗",
            "🤩", "🤔", "🤨", "😐", "😑", "😶", "🙄", "😏", "😣", "😥",
            "😮", "🤐", "😯", "😪", "😫", "😴", "😌", "😛", "😜", "😝",
            "🤤", "😒", "😓", "😔", "😕", "🙃", "🤑", "😲", "🙁", "😖",
            "😞", "😟", "😤", "😢", "😭", "😦", "😧", "😨", "😩", "🤯",
            "😬", "😰", "😱", "🥵", "🥶", "😳", "🤪", "😵", "🥴", "😠",
            "😡", "🤬", "😷", "🤒", "🤕", "🤢", "🤮", "🤧", "🥳", "🥺",
            "🤠", "🤡", "🤥", "🤫", "🤭", "🧐", "🤓", "😈", "👿", "👹",
            "👺", "💀", "👻", "👽", "👾", "🤖", "😺", "😸", "😹", "😻",
            "😼", "😽", "🙀", "😿", "😾"
        ]
        
        row = 0
        col = 0
        frame = tk.Frame(picker)
        frame.pack(fill="both", expand=True)
        
        for emoji in emojis:
            btn = tk.Button(frame, text=emoji, font=(FONT_FAMILY, 16), command=lambda e=emoji: self.insert_emoji(e, picker))
            btn.grid(row=row, column=col, padx=2, pady=2)
            col += 1
            if col == 10:
                col = 0
                row += 1
    
    def insert_emoji(self, emoji, picker):
        """Insert selected emoji into message entry."""
        self.message_entry.insert(tk.INSERT, emoji)
        picker.destroy()
    
    # Tier 1: Typing detection
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
                
                # TIER 2: Initialize file transfer manager
                self.file_transfer_manager = FileTransferManager(self.socket, self.username, self.ui_queue)
                self.file_transfer_panel.transfer_manager = self.file_transfer_manager
                
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
        """Receive messages thread - ALL MESSAGES ARE TEXT."""
        while self.running:
            try:
                encrypted_data = self.socket.recv(BUFFER_SIZE)
                
                if not encrypted_data:
                    self.connected = False
                    self.root.after(0, self.handle_disconnection)
                    break
                
                # Decrypt and decode as UTF-8 (ALL messages are text now)
                decrypted_data = decrypt(encrypted_data)
                text_data = decrypted_data.decode('utf-8')
                
                # Add to message buffer
                self.message_buffer.add_data(text_data)
                
                # Process complete messages
                for message in self.message_buffer.get_messages():
                    self.process_message(message)
            
            except Exception as e:
                if self.running:
                    print(f"Receive error: {e}")
                    self.connected = False
                    self.root.after(0, self.handle_disconnection)
                break
    
    def process_message(self, raw_message: str, raw_bytes: bytes = None):
        """Process received message (Tier 1 + Tier 2)."""
        parsed = parse_message(raw_message)
        
        if not parsed:
            return
        
        msg_type = parsed['type']
        sender = parsed['sender']
        content = parsed['content']
        
        # ===== TIER 1: TEXT MESSAGES =====
        if msg_type == MSG_TYPE_TEXT or msg_type == MSG_TYPE_MESSAGE_DELIVERED:
            try:
                msg_data = json.loads(content)
                text = msg_data.get('text', content)
                msg_id = msg_data.get('msg_id', 0)
                timestamp = msg_data.get('timestamp', '')
                
                if msg_id:
                    self.received_message_ids.append(msg_id)
                    self.root.after(1000, lambda: self.send_read_ack(msg_id))
            except:
                text = content
                msg_id = 0
                timestamp = ''
            
            tag = "self" if sender == self.username else "others"
            self.root.after(0, lambda: self.display_message(sender, text, tag, msg_id, timestamp))
        
        # ===== TIER 1: OTHER MESSAGES =====
        elif msg_type == MSG_TYPE_DELIVERY_ACK or msg_type == 'DELIVERY_ACK':
            pass  # Handle if needed
        
        elif msg_type == MSG_TYPE_READ_ACK or msg_type == 'READ_ACK':
            pass  # Handle if needed
        
        elif msg_type == MSG_TYPE_TYPING_START or msg_type == 'TYPING_START':
            self.typing_users.add(sender)
            self.root.after(0, self.update_typing_indicator)
        
        elif msg_type == MSG_TYPE_TYPING_STOP or msg_type == 'TYPING_STOP':
            self.typing_users.discard(sender)
            self.root.after(0, self.update_typing_indicator)
        
        elif msg_type == MSG_TYPE_STATUS_CHANGE or msg_type == 'STATUS_CHANGE' or msg_type == MSG_TYPE_STATUS_UPDATE or msg_type == 'STATUS_UPDATE':
            self.user_statuses[sender] = content
            self.root.after(0, self.refresh_user_list)
        
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
        
        # ===== TIER 2: FILE TRANSFER PROTOCOL =====
        elif msg_type == MSG_TYPE_FILE_OFFER:
            offer_data = parse_file_offer(content)
            file_id = offer_data.get('file_id')
            filename = offer_data.get('filename')
            filesize = offer_data.get('filesize')
            
            # Create receive transfer
            self.file_transfer_manager.create_receive_transfer(file_id, sender, filename, filesize)
        
        elif msg_type == MSG_TYPE_FILE_ACCEPT:
            accept_data = json.loads(content)
            file_id = accept_data.get('file_id')
            self.file_transfer_manager.handle_accept(file_id)
        
        elif msg_type == MSG_TYPE_FILE_REJECT:
            reject_data = json.loads(content)
            file_id = reject_data.get('file_id')
            self.ui_queue.put(('file_rejected', {'file_id': file_id}))
        
        elif msg_type == MSG_TYPE_FILE_DATA:
            try:
                # Parse JSON payload
                data_payload = json.loads(content)
                
                file_id = data_payload['file_id']
                offset = data_payload['offset']
                encoded_data = data_payload['data']
                
                # Base64 decode to get original binary chunk
                chunk_data = base64.b64decode(encoded_data)
                
                # Write to file
                self.file_transfer_manager.handle_data_chunk(
                    file_id, offset, chunk_data
                )
            
            except Exception as e:
                print(f"Error handling FILE_DATA: {e}")

        
        elif msg_type == MSG_TYPE_FILE_PAUSE:
            pause_data = json.loads(content)
            file_id = pause_data.get('file_id')
            offset = pause_data.get('offset')
            self.file_transfer_manager.handle_pause(file_id, offset)
        
        elif msg_type == MSG_TYPE_FILE_RESUME:
            resume_data = json.loads(content)
            file_id = resume_data.get('file_id')
            offset = resume_data.get('offset')
            self.file_transfer_manager.handle_resume(file_id, offset)
        
        elif msg_type == MSG_TYPE_FILE_CANCEL:
            cancel_data = json.loads(content)
            file_id = cancel_data.get('file_id')
            self.file_transfer_manager.handle_cancel(file_id)
        
        elif msg_type == MSG_TYPE_FILE_COMPLETE:
            complete_data = json.loads(content)
            file_id = complete_data.get('file_id')
            self.file_transfer_manager.handle_complete(file_id)
    
    def process_ui_queue(self):
        """
        Process UI updates from worker threads.
        MUST run in main thread to safely update Tkinter widgets.
        """
        try:
            while not self.ui_queue.empty():
                event_type, data = self.ui_queue.get_nowait()
                
                if event_type == 'send_offer':
                    self.file_transfer_panel.add_send_transfer(
                        data['file_id'],
                        data['filename'],
                        data['filesize']
                    )
                
                elif event_type == 'receive_offer':
                    self.file_transfer_panel.add_receive_transfer(
                        data['file_id'],
                        data['sender'],
                        data['filename'],
                        data['filesize']
                    )
                
                elif event_type == 'send_progress':
                    self.file_transfer_panel.update_progress(data['file_id'], data['progress'])
                
                elif event_type == 'receive_progress':
                    self.file_transfer_panel.update_progress(data['file_id'], data['progress'])
                
                elif event_type == 'send_paused':
                    self.file_transfer_panel.mark_paused(data['file_id'])
                
                elif event_type == 'receive_paused':
                    self.file_transfer_panel.mark_paused(data['file_id'])
                
                elif event_type == 'send_resumed':
                    self.file_transfer_panel.mark_resumed(data['file_id'])
                
                elif event_type == 'receive_resumed':
                    self.file_transfer_panel.mark_resumed(data['file_id'])
                
                elif event_type == 'send_complete':
                    self.file_transfer_panel.mark_completed(data['file_id'])
                    self.display_message("FILE", f"✓ Sent successfully", "file")
                
                elif event_type == 'receive_complete':
                    self.file_transfer_panel.mark_completed(data['file_id'])
                    filepath = data.get('filepath', '')
                    self.display_message("FILE", f"✓ Downloaded: {os.path.basename(filepath)}", "file")
                
                elif event_type == 'send_cancelled':
                    self.file_transfer_panel.mark_cancelled(data['file_id'])
                
                elif event_type == 'receive_cancelled':
                    self.file_transfer_panel.mark_cancelled(data['file_id'])
                
                elif event_type == 'receive_accepted':
                    self.file_transfer_panel.set_status(data['file_id'], "Downloading...", SUCCESS_COLOR)
                
                elif event_type == 'receive_rejected':
                    self.file_transfer_panel.set_status(data['file_id'], "Rejected", ERROR_COLOR)
                
                elif event_type == 'file_rejected':
                    file_id = data['file_id']
                    self.file_transfer_panel.set_status(file_id, "Rejected by receiver", ERROR_COLOR)
                
                elif event_type == 'error':
                    messagebox.showerror("Error", data)
        
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_ui_queue)
    
    def send_message(self):
        """Send text message."""
        text = self.message_entry.get().strip()
        
        if not text or not self.connected:
            return
        
        self.stop_typing()
        
        try:
            client_msg_id = int(time.time() * 1000)
            message = create_message(
                MSG_TYPE_MESSAGE_SENT,
                self.username,
                json.dumps({'text': text, 'client_id': client_msg_id})
            )
            encrypted = encrypt(message.encode('utf-8'))
            self.socket.sendall(encrypted)
            
            self.message_entry.delete(0, tk.END)
            self.display_message(self.username, text, "self", client_msg_id)
        
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
        """Send file via Tier 2 protocol."""
        if not self.connected:
            return
        
        filepath = filedialog.askopenfilename(title="Select file")
        
        if not filepath:
            return
        
        # Create transfer via manager
        file_id = self.file_transfer_manager.create_send_transfer(filepath)
        
        if file_id:
            # Show file panel if hidden
            self.file_transfer_panel.show()
    
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
    
    def display_message(self, sender: str, text: str, tag: str, msg_id: int = 0, timestamp: str = ''):
        """Display message with enhanced timestamp."""
        self.chat_display.config(state="normal")
        
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%H:%M")
            except:
                time_str = datetime.now().strftime("%H:%M")
        else:
            time_str = datetime.now().strftime("%H:%M")
        
        now = datetime.now()
        if hasattr(self, 'last_message_date') and self.last_message_date:
            if self.last_message_date != now.date():
                date_text = f"\n───── {now.strftime('%B %d, %Y')} ─────\n"
                self.chat_display.insert(tk.END, date_text, "timestamp")
        
        self.last_message_date = now.date()
        
        self.chat_display.insert(tk.END, f"[{time_str}] ", "timestamp")
        self.chat_display.insert(tk.END, f"{sender}: ", tag)
        self.chat_display.insert(tk.END, f"{text}")
        
        if sender == self.username and msg_id:
            self.chat_display.insert(tk.END, " ✓", "timestamp")
            self.sent_message_ids[msg_id] = {'text': text, 'status': 'sent'}
        
        self.chat_display.insert(tk.END, "\n")
        
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
    
    def handle_disconnection(self):
        """Handle server disconnection."""
        self.display_message("SERVER", "⚠ Connection lost", "buzz")
    
    def send_read_ack(self, msg_id: int):
        """Send read acknowledgment for a message."""
        if not self.connected or msg_id == 0:
            return
        
        try:
            read_msg = create_message(
                MSG_TYPE_MESSAGE_READ,
                self.username,
                json.dumps({'msg_id': msg_id})
            )
            encrypted = encrypt(read_msg.encode('utf-8'))
            self.socket.sendall(encrypted)
        except Exception as e:
            print(f"Read ACK error: {e}")
    
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