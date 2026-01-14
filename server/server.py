import json
import socket
import threading
import sys
import os
from datetime import datetime
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    MESSAGE_ID_START, MSG_TYPE_MESSAGE_DELIVERED, MSG_TYPE_MESSAGE_READ, MSG_TYPE_MESSAGE_SENT, MSG_TYPE_STATUS_CHANGE, MSG_TYPE_STATUS_UPDATE, MSG_TYPE_TYPING_START, MSG_TYPE_TYPING_STOP, STATUS_ONLINE, TCP_HOST, TCP_PORT, MAX_CLIENTS, BUFFER_SIZE,
    USER_DATABASE, MSG_TYPE_AUTH, MSG_TYPE_AUTH_OK, MSG_TYPE_AUTH_FAIL
)
from common.protocol import (
    create_delivered_ack, create_read_ack, parse_message, create_message, create_text_message,
    create_user_list_message, create_error_message,
    MessageBuffer, MSG_TYPE_TEXT, MSG_TYPE_FILE, MSG_TYPE_BUZZ,
    MSG_TYPE_USER_JOIN, MSG_TYPE_USER_LEAVE, MSG_TYPE_FILE_CHUNK, parse_message_with_id
)
from common.encryption import encrypt, decrypt


# ==================== SERVER CLASS ====================

class ChatServer:
    """
    Multi-threaded TCP chat server.
    
    Manages client connections, authentication, and message routing.
    """
    
    def __init__(self, host: str = TCP_HOST, port: int = TCP_PORT):
        """
        Initialize chat server with TIER 1 feature support.
        """
        self.host = host
        self.port = port
        self.server_socket = None
        
        # Thread-safe client management
        self.clients = {}  # {username: socket}
        self.clients_lock = threading.Lock()
        
        # TIER 1: Server-authoritative user state
        self.user_sessions = {}  # {username: {'socket': socket, 'address': addr, 'login_time': time, 'status': str}}
        self.user_status = {}    # {username: 'online'/'busy'/'offline'} - PRIMARY STATUS STORE
        self.typing_users = set()  # Currently typing users
        self.session_ids = {}    # {username: session_id} for reconnect
        
        # TIER 1: Message delivery tracking
        self.message_counter = MESSAGE_ID_START  # Auto-incrementing message IDs
        self.pending_messages = {}  # {msg_id: {'sender': str, 'recipients': set(), 'delivered': set(), 'read': set()}}
        self.message_counter_lock = threading.Lock()
        
        # File transfer tracking
        self.file_transfers = {}
        
        # Server state
        self.running = False
        self.start_time = None
    
    def get_next_message_id(self) -> int:
        """
        Get next unique message ID (thread-safe).
        
        Returns:
            int: Unique message ID
        """
        with self.message_counter_lock:
            msg_id = self.message_counter
            self.message_counter += 1
            return msg_id
    
    def start(self):
        """
        Start the TCP server and begin accepting connections.
        """
        try:
            # Create TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set socket options
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address
            self.server_socket.bind((self.host, self.port))
            
            # Listen for connections
            self.server_socket.listen(MAX_CLIENTS)
            
            self.running = True
            self.start_time = datetime.now()
            
            print("=" * 60)
            print(f"✓ Chat Server Started")
            print(f"  Host: {self.host}")
            print(f"  Port: {self.port}")
            print(f"  Max Clients: {MAX_CLIENTS}")
            print(f"  Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 60)
            print(f"\nWaiting for connections...\n")
            
            # Accept connections loop
            while self.running:
                try:
                    # Accept new connection
                    client_socket, client_address = self.server_socket.accept()
                    
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] New connection from {client_address}")
                    
                    # Create thread for client
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
        """
        Stop the server and close all connections.
        """
        self.running = False
        
        # Close all client connections
        with self.clients_lock:
            for username, client_socket in list(self.clients.items()):
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("\n✓ Server stopped\n")
    
    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        """
        Handle individual client connection.
        
        Args:
            client_socket: Client's socket object
            client_address: Client's (IP, port) tuple
        """
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
                
                # TIER 1: Initialize server-authoritative status
                self.user_status[username] = STATUS_ONLINE
                
                self.user_sessions[username] = {
                    'socket': client_socket,
                    'address': client_address,
                    'login_time': datetime.now(),
                    'status': STATUS_ONLINE  # Redundant but explicit
                }
                
                # Generate session ID for reconnect
                import uuid
                session_id = str(uuid.uuid4())
                self.session_ids[username] = session_id
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ {username} authenticated from {client_address}")
            
            # Send session ID to client
            from common.protocol import create_session_message
            session_msg = create_session_message(session_id)
            self.send_raw(client_socket, session_msg)
            
            # Notify all clients about new user
            join_msg = create_message(MSG_TYPE_USER_JOIN, "SERVER", username)
            self.broadcast_message(join_msg, exclude=username)
            
            # Send welcome message
            welcome_text = f"Welcome to the chat, {username}!"
            welcome_msg = create_text_message("SERVER", welcome_text)
            self.send_to_client(username, welcome_msg)
            
            # Send online users list
            self.send_user_list(username)
            
            # Main communication loop
            while self.running:
                try:
                    # Receive data
                    encrypted_data = client_socket.recv(BUFFER_SIZE)
                    
                    if not encrypted_data:
                        break  # Client disconnected
                    
                    # Decrypt data
                    data = decrypt(encrypted_data).decode('utf-8', errors='ignore')
                    
                    # Add to buffer
                    message_buffer.add_data(data)
                    
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
            # Cleanup
            if username:
                self.remove_client(username)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ {username} disconnected")
                
                # Notify others
                leave_msg = create_message(MSG_TYPE_USER_LEAVE, "SERVER", username)
                self.broadcast_message(leave_msg)
            
            try:
                client_socket.close()
            except:
                pass
    
    def authenticate_client(self, client_socket: socket.socket, client_address: tuple) -> str:
        """
        Authenticate client user.
        
        Args:
            client_socket: Client socket
            client_address: Client address
        
        Returns:
            str: Username if authenticated, None otherwise
        """
        try:
            # Wait for authentication message
            client_socket.settimeout(30)  # 30 second auth timeout
            encrypted_data = client_socket.recv(BUFFER_SIZE)
            client_socket.settimeout(None)
            
            if not encrypted_data:
                return None
            
            # Decrypt and parse
            data = decrypt(encrypted_data).decode('utf-8', errors='ignore')
            parsed = parse_message(data)
            
            if not parsed or parsed['type'] != MSG_TYPE_AUTH:
                error_msg = create_error_message("Invalid authentication format")
                self.send_raw(client_socket, error_msg)
                return None
            
            # Extract credentials
            import json
            try:
                credentials = json.loads(parsed['content'])
                username = credentials.get('username', '')
                password = credentials.get('password', '')
            except:
                error_msg = create_error_message("Invalid credentials format")
                self.send_raw(client_socket, error_msg)
                return None
            
            # Verify credentials
            if username in USER_DATABASE and USER_DATABASE[username] == password:
                # Check if already logged in
                with self.clients_lock:
                    if username in self.clients:
                        error_msg = create_error_message("User already logged in")
                        self.send_raw(client_socket, error_msg)
                        return None
                
                # Authentication successful
                success_msg = create_message(MSG_TYPE_AUTH_OK, "SERVER", "Authentication successful")
                self.send_raw(client_socket, success_msg)
                return username
            else:
                # Authentication failed
                fail_msg = create_message(MSG_TYPE_AUTH_FAIL, "SERVER", "Invalid username or password")
                self.send_raw(client_socket, fail_msg)
                return None
        
        except socket.timeout:
            print(f"Authentication timeout for {client_address}")
            return None
        except Exception as e:
            print(f"Authentication error for {client_address}: {e}")
            return None
    
    def process_message(self, username: str, raw_message: str):
        """
        Process received message from client.
        TIER 1: Full server-side logic for all features.
        """
        parsed = parse_message(raw_message)
        
        if not parsed:
            return
        
        msg_type = parsed['type']
        content = parsed['content']
        
        # ===== TIER 1: TEXT MESSAGE WITH DELIVERY TRACKING =====
        # FIX: Handle BOTH old TEXT and new MESSAGE_SENT
        if msg_type == MSG_TYPE_MESSAGE_SENT or msg_type == MSG_TYPE_TEXT:
            # Assign message ID and timestamp (server-authoritative)
            msg_id = self.get_next_message_id()
            timestamp = datetime.now().isoformat()
            
            # Parse content (handle both formats)
            if msg_type == MSG_TYPE_MESSAGE_SENT:
                try:
                    msg_data = json.loads(content)
                    text = msg_data.get('text', content)
                except:
                    text = content
            else:
                # Old-style TEXT message
                text = content
            
            # Track message for delivery
            with self.clients_lock:
                recipients = set(self.clients.keys()) - {username}
            
            self.pending_messages[msg_id] = {
                'sender': username,
                'text': text,
                'timestamp': timestamp,
                'recipients': recipients.copy(),
                'delivered': set(),
                'read': set()
            }
            
            # FIX: Broadcast using MESSAGE_DELIVERED (with full data)
            msg_content = json.dumps({
                'text': text,
                'msg_id': msg_id,
                'timestamp': timestamp
            })
            broadcast_msg = create_message(MSG_TYPE_MESSAGE_DELIVERED, username, msg_content)
            
            # Deliver to all recipients
            delivered_count = 0
            with self.clients_lock:
                for recipient, client_socket in self.clients.items():
                    if recipient != username:
                        try:
                            encrypted = encrypt(broadcast_msg.encode('utf-8'))
                            client_socket.sendall(encrypted)
                            self.pending_messages[msg_id]['delivered'].add(recipient)
                            delivered_count += 1
                        except Exception as e:
                            print(f"Failed to deliver to {recipient}: {e}")
            
            # Send delivery ack to sender
            delivery_ack = create_delivered_ack(msg_id, f"{delivered_count} recipients")
            self.send_to_client(username, delivery_ack)
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username}: {text[:50]} [MSG_ID:{msg_id}, DELIVERED:{delivered_count}]")
    
        
        # ===== TIER 1: TYPING INDICATORS (SERVER RELAYS) =====
        elif msg_type == MSG_TYPE_TYPING_START or msg_type == 'TYPING_START':
            with self.clients_lock:
                self.typing_users.add(username)
            # Relay to ALL other clients (server does not filter)
            self.broadcast_message(raw_message, exclude=username)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} started typing")
        
        elif msg_type == MSG_TYPE_TYPING_STOP or msg_type == 'TYPING_STOP':
            with self.clients_lock:
                self.typing_users.discard(username)
            self.broadcast_message(raw_message, exclude=username)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} stopped typing")
        
        # ===== TIER 1: STATUS CHANGE (SERVER-AUTHORITATIVE) =====
        elif msg_type == MSG_TYPE_STATUS_CHANGE or msg_type == 'STATUS_CHANGE':
            new_status = content
            
            # SERVER updates status (single source of truth)
            with self.clients_lock:
                self.user_status[username] = new_status
                if username in self.user_sessions:
                    self.user_sessions[username]['status'] = new_status
            
            # Broadcast status update to ALL clients (including sender for confirmation)
            status_update = create_message(MSG_TYPE_STATUS_UPDATE, username, new_status)
            self.broadcast_message(status_update)  # No exclude - everyone gets it
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} status → {new_status}")
        
        # ===== TIER 1: READ ACKNOWLEDGMENT =====
        elif msg_type == MSG_TYPE_MESSAGE_READ or msg_type == 'MSG_READ':
            try:
                read_data = json.loads(content)
                msg_id = read_data.get('msg_id')
                
                if msg_id and msg_id in self.pending_messages:
                    self.pending_messages[msg_id]['read'].add(username)
                    
                    # Notify original sender
                    original_sender = self.pending_messages[msg_id]['sender']
                    read_ack = create_read_ack(msg_id, username)
                    self.send_to_client(original_sender, read_ack)
                    
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Message {msg_id} read by {username}")
            except:
                pass
        
        # ===== EXISTING: BUZZ =====
        elif msg_type == MSG_TYPE_BUZZ:
            self.broadcast_message(raw_message, exclude=username)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} sent a BUZZ")
        
        # ===== EXISTING: FILE TRANSFER =====
        elif msg_type == MSG_TYPE_FILE:
            self.broadcast_message(raw_message, exclude=username)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} initiated file transfer")
        
        elif msg_type == MSG_TYPE_FILE_CHUNK:
            self.broadcast_raw(raw_message.encode('utf-8'), exclude=username)
    
    def broadcast_message(self, message: str, exclude: str = None):
        """
        Broadcast message to all connected clients.
        
        Args:
            message (str): Message to broadcast
            exclude (str): Username to exclude from broadcast
        """
        with self.clients_lock:
            for username, client_socket in list(self.clients.items()):
                if username == exclude:
                    continue
                
                try:
                    # Encrypt and send
                    encrypted = encrypt(message.encode('utf-8'))
                    client_socket.sendall(encrypted)
                except Exception as e:
                    print(f"Error sending to {username}: {e}")
    
    def broadcast_raw(self, data: bytes, exclude: str = None):
        """
        Broadcast raw bytes to all connected clients.
        
        Args:
            data (bytes): Raw data to broadcast
            exclude (str): Username to exclude
        """
        with self.clients_lock:
            for username, client_socket in list(self.clients.items()):
                if username == exclude:
                    continue
                
                try:
                    encrypted = encrypt(data)
                    client_socket.sendall(encrypted)
                except Exception as e:
                    print(f"Error sending to {username}: {e}")
    
    def send_to_client(self, username: str, message: str):
        """
        Send message to specific client.
        
        Args:
            username (str): Target username
            message (str): Message to send
        """
        with self.clients_lock:
            if username in self.clients:
                try:
                    encrypted = encrypt(message.encode('utf-8'))
                    self.clients[username].sendall(encrypted)
                except Exception as e:
                    print(f"Error sending to {username}: {e}")
    
    def send_raw(self, client_socket: socket.socket, message: str):
        """
        Send raw message to socket (for auth phase).
        
        Args:
            client_socket: Socket to send to
            message: Message to send
        """
        try:
            encrypted = encrypt(message.encode('utf-8'))
            client_socket.sendall(encrypted)
        except Exception as e:
            print(f"Error sending raw message: {e}")
    
    def send_user_list(self, username: str):
        """
        Send list of online users with their status to specific client.
        
        Args:
            username (str): Target username
        """
        with self.clients_lock:
            # NEW: Include status information
            user_data = []
            for user in self.clients.keys():
                status = self.user_status.get(user, 'online')
                user_data.append({
                    'username': user,
                    'status': status,
                    'typing': user in self.typing_users
                })
        
        import json
        user_list_json = json.dumps(user_data)
        user_list_msg = f"USER_LIST|SERVER|{user_list_json}<END>"
        self.send_to_client(username, user_list_msg)
    
    def remove_client(self, username: str):
        """
        Remove client from active connections.
        
        Args:
            username (str): Username to remove
        """
        with self.clients_lock:
            if username in self.clients:
                del self.clients[username]
            if username in self.user_sessions:
                del self.user_sessions[username]
            # NEW: Clean up status tracking
            if username in self.user_status:
                self.user_status[username] = 'offline'
            self.typing_users.discard(username)
    
    def get_server_stats(self) -> dict:
        """
        Get server statistics.
        
        Returns:
            dict: Server stats
        """
        uptime = datetime.now() - self.start_time if self.start_time else None
        
        with self.clients_lock:
            online_count = len(self.clients)
            online_users = list(self.clients.keys())
        
        return {
            'uptime': str(uptime).split('.')[0] if uptime else "N/A",
            'online_count': online_count,
            'online_users': online_users,
            'max_clients': MAX_CLIENTS
        }


# ==================== MAIN ====================

def main():
    """
    Main entry point for server.
    """
    print("\n" + "=" * 60)
    print("  MULTI-CLIENT CHAT SERVER")
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