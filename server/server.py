import json
import socket
import threading
import sys
import os
from datetime import datetime
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    MESSAGE_ID_START, MSG_DELIMITER, MSG_TYPE_MESSAGE_DELIVERED, MSG_TYPE_MESSAGE_READ, 
    MSG_TYPE_MESSAGE_SENT, MSG_TYPE_STATUS_CHANGE, MSG_TYPE_STATUS_UPDATE, 
    MSG_TYPE_TYPING_START, MSG_TYPE_TYPING_STOP, STATUS_ONLINE, STATUS_BUSY, STATUS_OFFLINE,
    TCP_HOST, TCP_PORT, MAX_CLIENTS, BUFFER_SIZE,
    USER_DATABASE, MSG_TYPE_AUTH, MSG_TYPE_AUTH_OK, MSG_TYPE_AUTH_FAIL,
    # Tier 2: File transfer
    MSG_TYPE_FILE_OFFER, MSG_TYPE_FILE_ACCEPT, MSG_TYPE_FILE_REJECT,
    MSG_TYPE_FILE_DATA, MSG_TYPE_FILE_PAUSE, MSG_TYPE_FILE_RESUME,
    MSG_TYPE_FILE_CANCEL, MSG_TYPE_FILE_ACK, MSG_TYPE_FILE_COMPLETE,
    FILE_STATE_OFFERED, FILE_STATE_ACCEPTED, FILE_STATE_TRANSFERRING,
    FILE_STATE_PAUSED, FILE_STATE_COMPLETED, FILE_STATE_CANCELLED
)
from common.protocol import (
    create_delivered_ack, create_read_ack, parse_message, create_message, 
    create_text_message, create_user_list_message, create_error_message,
    MessageBuffer, MSG_TYPE_TEXT, MSG_TYPE_FILE, MSG_TYPE_BUZZ,
    MSG_TYPE_USER_JOIN, MSG_TYPE_USER_LEAVE, MSG_TYPE_FILE_CHUNK, 
    parse_message_with_id, parse_file_offer, create_file_cancel_message
)
from common.encryption import encrypt, decrypt


class ChatServer:
    """
    Multi-threaded TCP chat server with Tier 2 file transfer relay.
    
    Server acts as relay for file transfers - does NOT store files.
    Tracks transfer state and routes messages between sender/receiver.
    """
    
    def __init__(self, host: str = TCP_HOST, port: int = TCP_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        
        # Thread-safe client management
        self.clients = {}
        self.clients_lock = threading.Lock()
        
        # Tier 1: Server-authoritative user state
        self.user_sessions = {}
        self.user_status = {}
        self.typing_users = set()
        self.session_ids = {}
        
        # Tier 1: Message delivery tracking
        self.message_counter = MESSAGE_ID_START
        self.pending_messages = {}
        self.message_counter_lock = threading.Lock()
        
        # TIER 2: File transfer tracking
        # {file_id: {'sender': str, 'receiver': str, 'filename': str, 
        #            'filesize': int, 'state': str, 'offset': int}}
        self.file_transfers = {}
        self.file_transfers_lock = threading.Lock()
        
        # Server state
        self.running = False
        self.start_time = None
    
    def get_next_message_id(self) -> int:
        """Get next unique message ID (thread-safe)."""
        with self.message_counter_lock:
            msg_id = self.message_counter
            self.message_counter += 1
            return msg_id
    
    def start(self):
        """Start the TCP server and begin accepting connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CLIENTS)
            
            self.running = True
            self.start_time = datetime.now()
            
            print("=" * 60)
            print(f"✓ Chat Server Started (Tier 2: File Transfer - Base64)")
            print(f"  Host: {self.host}")
            print(f"  Port: {self.port}")
            print(f"  Max Clients: {MAX_CLIENTS}")
            print(f"  Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 60)
            print(f"\nWaiting for connections...\n")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] New connection from {client_address}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    print("\n\n⚠ Server shutting down...")
                    break
                except Exception as e:
                    print(f"Error accepting connection: {e}")
        
        except Exception as e:
            print(f"✗ Failed to start server: {e}")
        
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server and close all connections."""
        self.running = False
        
        with self.clients_lock:
            for username, client_socket in list(self.clients.items()):
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("\n✓ Server stopped\n")
    
    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle individual client connection."""
        username = None
        message_buffer = MessageBuffer()
        
        try:
            # Authentication phase
            username = self.authenticate_client(client_socket, client_address)
            
            if not username:
                client_socket.close()
                return
            
            # Add to clients dictionary
            with self.clients_lock:
                self.clients[username] = client_socket
                self.user_status[username] = STATUS_ONLINE
                self.user_sessions[username] = {
                    'socket': client_socket,
                    'address': client_address,
                    'login_time': datetime.now(),
                    'status': STATUS_ONLINE
                }
                
                import uuid
                session_id = str(uuid.uuid4())
                self.session_ids[username] = session_id
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ {username} authenticated from {client_address}")
            
            # Send session ID
            from common.protocol import create_session_message
            session_msg = create_session_message(session_id)
            self.send_raw(client_socket, session_msg)
            
            # Notify others
            join_msg = create_message(MSG_TYPE_USER_JOIN, "SERVER", username)
            self.broadcast_message(join_msg, exclude=username)
            
            # Welcome message
            welcome_text = f"Welcome to the chat, {username}!"
            welcome_msg = create_text_message("SERVER", welcome_text)
            self.send_to_client(username, welcome_msg)
            
            # Broadcast updated user list to all clients (including new user)
            self.broadcast_user_list()
            
            # Main communication loop - ALL MESSAGES ARE TEXT NOW
            while self.running:
                try:
                    encrypted_data = client_socket.recv(BUFFER_SIZE)
                    
                    if not encrypted_data:
                        break
                    
                    # Decrypt and decode as UTF-8 (ALL messages are text)
                    decrypted = decrypt(encrypted_data)
                    text = decrypted.decode('utf-8', errors='ignore')
                    
                    # Add to buffer
                    message_buffer.add_data(text)
                    
                    # Process complete messages
                    for raw_message in message_buffer.get_messages():
                        self.process_message(username, raw_message)
                
                except ConnectionResetError:
                    break
                except Exception as e:
                    print(f"Error handling {username}: {e}")
                    break
        
        except Exception as e:
            print(f"Error in client handler: {e}")
        
        finally:
            if username:
                self.remove_client(username)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ {username} disconnected")
                
                leave_msg = create_message(MSG_TYPE_USER_LEAVE, "SERVER", username)
                self.broadcast_message(leave_msg)
            
            try:
                client_socket.close()
            except:
                pass
    
    def authenticate_client(self, client_socket: socket.socket, client_address: tuple) -> str:
        """Authenticate client user."""
        try:
            client_socket.settimeout(30)
            encrypted_data = client_socket.recv(BUFFER_SIZE)
            client_socket.settimeout(None)
            
            if not encrypted_data:
                return None
            
            data = decrypt(encrypted_data).decode('utf-8', errors='ignore')
            parsed = parse_message(data)
            
            if not parsed or parsed['type'] != MSG_TYPE_AUTH:
                self.send_raw(client_socket, create_message(MSG_TYPE_AUTH_FAIL, "SERVER", "Invalid auth"))
                return None
            
            auth_data = json.loads(parsed['content'])
            username = auth_data.get('username')
            password = auth_data.get('password')
            
            if not username or not password:
                self.send_raw(client_socket, create_message(MSG_TYPE_AUTH_FAIL, "SERVER", "Missing credentials"))
                return None
            
            if username in USER_DATABASE and USER_DATABASE[username] == password:
                with self.clients_lock:
                    if username in self.clients:
                        self.send_raw(client_socket, create_message(MSG_TYPE_AUTH_FAIL, "SERVER", "User already online"))
                        return None
                
                auth_ok = create_message(MSG_TYPE_AUTH_OK, "SERVER", "")
                self.send_raw(client_socket, auth_ok)
                return username
            else:
                self.send_raw(client_socket, create_message(MSG_TYPE_AUTH_FAIL, "SERVER", "Invalid credentials"))
                return None
        
        except Exception as e:
            print(f"Auth error from {client_address}: {e}")
            return None
    
    def process_message(self, username: str, raw_message: str):
        """Process incoming message from client."""
        parsed = parse_message(raw_message)
        
        if not parsed:
            return
        
        msg_type = parsed['type']
        content = parsed['content']
        
        # Skip processing non-status messages if user is busy
        if self.user_status.get(username, STATUS_ONLINE) != STATUS_ONLINE and msg_type != MSG_TYPE_STATUS_CHANGE:
            return
        
        # ===== TIER 1: TEXT MESSAGES =====
        if msg_type == MSG_TYPE_TEXT or msg_type == MSG_TYPE_MESSAGE_SENT:
            # Parse with ID if present
            msg_data = parse_message_with_id(content)
            text = msg_data.get('text', content)
            
            # Generate server ID
            server_msg_id = self.get_next_message_id()
            
            # Create relayed message
            relayed_content = json.dumps({
                'text': text,
                'msg_id': server_msg_id,
                'timestamp': datetime.now().isoformat()
            })
            
            relayed_msg = create_message(MSG_TYPE_TEXT, username, relayed_content)
            
            # Broadcast to others
            self.broadcast_message(relayed_msg, exclude=username)
            
            # Send delivery ACK to sender
            delivery_ack = create_delivered_ack(server_msg_id, "all")
            self.send_to_client(username, delivery_ack)
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username}: {text}")
        
        # ===== TIER 1: BUZZ =====
        elif msg_type == MSG_TYPE_BUZZ:
            buzz_msg = create_message(MSG_TYPE_BUZZ, username, "")
            self.broadcast_message(buzz_msg, exclude=username)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} sent BUZZ")
        
        # ===== TIER 1: TYPING INDICATORS =====
        elif msg_type == MSG_TYPE_TYPING_START:
            self.typing_users.add(username)
            typing_msg = create_message(MSG_TYPE_TYPING_START, username, "")
            self.broadcast_message(typing_msg, exclude=username)
        
        elif msg_type == MSG_TYPE_TYPING_STOP:
            self.typing_users.discard(username)
            typing_msg = create_message(MSG_TYPE_TYPING_STOP, username, "")
            self.broadcast_message(typing_msg, exclude=username)
        
        # ===== TIER 1: STATUS CHANGE =====
        elif msg_type == MSG_TYPE_STATUS_CHANGE:
            new_status = content
            old_status = self.user_status.get(username, STATUS_ONLINE)
            if new_status in [STATUS_ONLINE, STATUS_BUSY]:
                self.user_status[username] = new_status
                if new_status == STATUS_BUSY:
                    self.typing_users.discard(username)
                    leave_text = f"{username} is busy, has"
                    leave_msg = create_message(MSG_TYPE_USER_LEAVE, "SERVER", leave_text)
                    self.broadcast_message(leave_msg)
                    # Cancel active file transfers
                    with self.file_transfers_lock:
                        to_cancel = [fid for fid, transfer in self.file_transfers.items()
                                    if transfer['sender'] == username or transfer.get('receiver') == username]
                        for file_id in to_cancel:
                            transfer = self.file_transfers[file_id]
                            sender = transfer['sender']
                            receiver = transfer['receiver']
                            cancel_msg = create_file_cancel_message("SERVER", file_id, "User busy")
                            if sender == username and receiver:
                                self.send_to_client(receiver, cancel_msg)
                            elif receiver == username and sender:
                                self.send_to_client(sender, cancel_msg)
                            del self.file_transfers[file_id]
                elif new_status == STATUS_ONLINE and old_status == STATUS_BUSY:
                    return_text = f"{username} has"
                    return_msg = create_message(MSG_TYPE_USER_JOIN, "SERVER", return_text)
                    self.broadcast_message(return_msg)
                status_msg = create_message(MSG_TYPE_STATUS_CHANGE, username, new_status)
                self.broadcast_message(status_msg, exclude=username)
                self.broadcast_user_list()
        
        # ===== TIER 1: READ ACK =====
        elif msg_type == MSG_TYPE_MESSAGE_READ:
            try:
                read_data = json.loads(content)
                msg_id = read_data.get('msg_id')
                if msg_id:
                    read_ack = create_read_ack(msg_id, username)
                    self.broadcast_message(read_ack, exclude=username)
            except:
                pass
        
        # ===== TIER 2: FILE TRANSFER PROTOCOL (BASE64) =====
        
        elif msg_type == MSG_TYPE_FILE_OFFER:
            # Parse offer
            offer_data = parse_file_offer(content)
            file_id = offer_data.get('file_id')
            filename = offer_data.get('filename')
            filesize = offer_data.get('filesize')
            
            # Track transfer (no specific receiver yet - broadcast to all)
            with self.file_transfers_lock:
                self.file_transfers[file_id] = {
                    'sender': username,
                    'receiver': None,  # Will be set on ACCEPT
                    'filename': filename,
                    'filesize': filesize,
                    'state': FILE_STATE_OFFERED,
                    'offset': 0,
                    'start_time': time.time()
                }
            
            # Relay offer to ALL other clients
            self.broadcast_message(raw_message, exclude=username)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE_OFFER: {username} → {filename} ({filesize} bytes) [ID:{file_id[:8]}]")
        
        elif msg_type == MSG_TYPE_FILE_ACCEPT:
            try:
                accept_data = json.loads(content)
                file_id = accept_data.get('file_id')
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        
                        # Set receiver
                        transfer['receiver'] = username
                        transfer['state'] = FILE_STATE_ACCEPTED
                        
                        # Relay ACCEPT to sender only
                        sender = transfer['sender']
                        self.send_to_client(sender, raw_message)
                        
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE_ACCEPT: {username} accepted from {sender} [ID:{file_id[:8]}]")
            except Exception as e:
                print(f"Error handling FILE_ACCEPT: {e}")
        
        elif msg_type == MSG_TYPE_FILE_REJECT:
            try:
                reject_data = json.loads(content)
                file_id = reject_data.get('file_id')
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        transfer['state'] = FILE_STATE_CANCELLED
                        
                        sender = transfer['sender']
                        self.send_to_client(sender, raw_message)
                        
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE_REJECT: {username} rejected [ID:{file_id[:8]}]")
            except Exception as e:
                print(f"Error handling FILE_REJECT: {e}")
        
        elif msg_type == MSG_TYPE_FILE_DATA:
            # FILE_DATA is now pure JSON with Base64 - relay as-is (text)
            try:
                data_payload = json.loads(content)
                file_id = data_payload.get('file_id')
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        transfer['state'] = FILE_STATE_TRANSFERRING
                        transfer['offset'] = data_payload.get('offset', 0) + data_payload.get('size', 0)
                        
                        receiver = transfer['receiver']
                        
                        # Relay entire message to receiver (it's text now)
                        if receiver:
                            self.send_to_client(receiver, raw_message)
            except Exception as e:
                print(f"Error relaying FILE_DATA: {e}")
        
        elif msg_type == MSG_TYPE_FILE_PAUSE:
            try:
                pause_data = json.loads(content)
                file_id = pause_data.get('file_id')
                offset = pause_data.get('offset', 0)
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        transfer['state'] = FILE_STATE_PAUSED
                        transfer['offset'] = offset
                        
                        # Relay to other party
                        sender = transfer['sender']
                        receiver = transfer['receiver']
                        target = receiver if username == sender else sender
                        
                        if target:
                            self.send_to_client(target, raw_message)
                        
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE_PAUSE: {username} paused at {offset} [ID:{file_id[:8]}]")
            except Exception as e:
                print(f"Error handling FILE_PAUSE: {e}")
        
        elif msg_type == MSG_TYPE_FILE_RESUME:
            try:
                resume_data = json.loads(content)
                file_id = resume_data.get('file_id')
                offset = resume_data.get('offset', 0)
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        transfer['state'] = FILE_STATE_TRANSFERRING
                        transfer['offset'] = offset
                        
                        # Relay to other party
                        sender = transfer['sender']
                        receiver = transfer['receiver']
                        target = receiver if username == sender else sender
                        
                        if target:
                            self.send_to_client(target, raw_message)
                        
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE_RESUME: {username} resumed from {offset} [ID:{file_id[:8]}]")
            except Exception as e:
                print(f"Error handling FILE_RESUME: {e}")
        
        elif msg_type == MSG_TYPE_FILE_CANCEL:
            try:
                cancel_data = json.loads(content)
                file_id = cancel_data.get('file_id')
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        transfer['state'] = FILE_STATE_CANCELLED
                        
                        # Relay to other party
                        sender = transfer['sender']
                        receiver = transfer['receiver']
                        target = receiver if username == sender else sender
                        
                        if target:
                            self.send_to_client(target, raw_message)
                        
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE_CANCEL: {username} cancelled [ID:{file_id[:8]}]")
                        
                        # Clean up
                        del self.file_transfers[file_id]
            except Exception as e:
                print(f"Error handling FILE_CANCEL: {e}")
        
        elif msg_type == MSG_TYPE_FILE_ACK:
            # Relay acknowledgment to sender
            try:
                ack_data = json.loads(content)
                file_id = ack_data.get('file_id')
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        sender = transfer['sender']
                        
                        self.send_to_client(sender, raw_message)
            except:
                pass
        
        elif msg_type == MSG_TYPE_FILE_COMPLETE:
            try:
                complete_data = json.loads(content)
                file_id = complete_data.get('file_id')
                
                with self.file_transfers_lock:
                    if file_id in self.file_transfers:
                        transfer = self.file_transfers[file_id]
                        transfer['state'] = FILE_STATE_COMPLETED
                        
                        # Relay to other party
                        sender = transfer['sender']
                        receiver = transfer['receiver']
                        target = receiver if username == sender else sender
                        
                        if target:
                            self.send_to_client(target, raw_message)
                        
                        duration = time.time() - transfer.get('start_time', time.time())
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] FILE_COMPLETE: {transfer['filename']} ({duration:.1f}s) [ID:{file_id[:8]}]")
                        
                        # Clean up
                        del self.file_transfers[file_id]
            except Exception as e:
                print(f"Error handling FILE_COMPLETE: {e}")
        
        # ===== LEGACY FILE TRANSFER (keep for compatibility) =====
        elif msg_type == MSG_TYPE_FILE:
            self.broadcast_message(raw_message, exclude=username)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} initiated legacy file transfer")
        
        elif msg_type == MSG_TYPE_FILE_CHUNK:
            self.broadcast_message(raw_message, exclude=username)
    
    def broadcast_message(self, message: str, exclude: str = None):
        """Broadcast message to all connected clients who are online."""
        with self.clients_lock:
            for username, client_socket in list(self.clients.items()):
                if username == exclude:
                    continue
                if self.user_status.get(username, STATUS_ONLINE) != STATUS_ONLINE:
                    continue
                
                try:
                    encrypted = encrypt(message.encode('utf-8'))
                    client_socket.sendall(encrypted)
                except Exception as e:
                    print(f"Error sending to {username}: {e}")
    
    def send_to_client(self, username: str, message: str):
        """Send message to specific client if they are online."""
        with self.clients_lock:
            if username in self.clients and self.user_status.get(username, STATUS_ONLINE) == STATUS_ONLINE:
                try:
                    encrypted = encrypt(message.encode('utf-8'))
                    self.clients[username].sendall(encrypted)
                except Exception as e:
                    print(f"Error sending to {username}: {e}")
    
    def send_raw(self, client_socket: socket.socket, message: str):
        """Send raw message to socket (for auth phase)."""
        try:
            encrypted = encrypt(message.encode('utf-8'))
            client_socket.sendall(encrypted)
        except Exception as e:
            print(f"Error sending raw message: {e}")
    
    def send_user_list(self, username: str):
        """Send list of online users with their status."""
        with self.clients_lock:
            user_data = []
            for user in self.clients.keys():
                status = self.user_status.get(user, STATUS_ONLINE)
                if status == STATUS_ONLINE:
                    user_data.append({
                        'username': user,
                        'status': status,
                        'typing': user in self.typing_users
                    })
        
        user_list_json = json.dumps(user_data)
        user_list_msg = f"USER_LIST|SERVER|{user_list_json}<END>"
        self.send_to_client(username, user_list_msg)
    
    def broadcast_user_list(self):
        """Broadcast updated user list to all connected clients."""
        with self.clients_lock:
            user_data = []
            for user in self.clients.keys():
                status = self.user_status.get(user, STATUS_ONLINE)
                if status == STATUS_ONLINE:
                    user_data.append({
                        'username': user,
                        'status': status,
                        'typing': user in self.typing_users
                    })
        
        user_list_json = json.dumps(user_data)
        user_list_msg = f"USER_LIST|SERVER|{user_list_json}<END>"
        self.broadcast_message(user_list_msg)
    
    def remove_client(self, username: str):
        """Remove client from active connections."""
        with self.clients_lock:
            if username in self.clients:
                del self.clients[username]
            if username in self.user_sessions:
                del self.user_sessions[username]
            if username in self.user_status:
                self.user_status[username] = STATUS_OFFLINE
            self.typing_users.discard(username)
        
        # Cancel any active file transfers
        with self.file_transfers_lock:
            to_cancel = [fid for fid, transfer in self.file_transfers.items()
                        if transfer['sender'] == username or transfer.get('receiver') == username]
            for file_id in to_cancel:
                del self.file_transfers[file_id]
        
        # Broadcast updated user list after removal
        self.broadcast_user_list()
    
    def get_server_stats(self) -> dict:
        """Get server statistics."""
        uptime = datetime.now() - self.start_time if self.start_time else None
        
        with self.clients_lock:
            online_count = len(self.clients)
            online_users = list(self.clients.keys())
        
        with self.file_transfers_lock:
            active_transfers = len(self.file_transfers)
        
        return {
            'uptime': str(uptime).split('.')[0] if uptime else "N/A",
            'online_count': online_count,
            'online_users': online_users,
            'max_clients': MAX_CLIENTS,
            'active_file_transfers': active_transfers
        }


def main():
    """Main entry point for server."""
    print("\n" + "=" * 60)
    print("  MULTI-CLIENT CHAT SERVER - TIER 2: FILE TRANSFER (BASE64)")
    print("=" * 60 + "\n")
    
    server = ChatServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
    finally:
        server.stop()

if __name__ == "__main__":
    main()