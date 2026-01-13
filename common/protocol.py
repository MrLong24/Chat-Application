import json
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    MSG_TYPE_TEXT, MSG_TYPE_FILE, MSG_TYPE_BUZZ,
    MSG_TYPE_USER_JOIN, MSG_TYPE_USER_LEAVE, MSG_TYPE_USER_LIST,
    MSG_TYPE_AUTH, MSG_TYPE_AUTH_OK, MSG_TYPE_AUTH_FAIL,
    MSG_TYPE_ERROR, MSG_DELIMITER, MSG_TYPE_FILE_CHUNK,
    MSG_TYPE_FILE_COMPLETE, MSG_TYPE_TYPING_START, MSG_TYPE_TYPING_STOP,
    MSG_TYPE_STATUS_CHANGE, MSG_TYPE_RECONNECT, MSG_TYPE_SESSION_ID
)


# ==================== MESSAGE CREATION ====================

def create_message(msg_type: str, sender: str, content: str = "") -> str:
    """
    Create a formatted protocol message.
    
    Args:
        msg_type (str): Type of message (TEXT, FILE, BUZZ, etc.)
        sender (str): Username of sender
        content (str): Message content
    
    Returns:
        str: Formatted message ready for transmission
    
    Example:
        >>> msg = create_message("TEXT", "alice", "Hello!")
        >>> print(msg)
        TEXT|alice|Hello!<END>
    """
    return f"{msg_type}|{sender}|{content}{MSG_DELIMITER}"


def create_text_message(sender: str, text: str) -> str:
    """
    Create a text message.
    
    Args:
        sender (str): Username
        text (str): Message text
    
    Returns:
        str: Formatted text message
    """
    return create_message(MSG_TYPE_TEXT, sender, text)


def create_file_message(sender: str, filename: str, filesize: int) -> str:
    """
    Create a file transfer initialization message.
    
    Args:
        sender (str): Username
        filename (str): Name of file
        filesize (int): Size of file in bytes
    
    Returns:
        str: Formatted file message
    """
    content = f"{filename}|{filesize}"
    return create_message(MSG_TYPE_FILE, sender, content)


def create_file_chunk_message(sender: str, chunk_data: bytes, chunk_num: int) -> bytes:
    """
    Create a file chunk message with binary data.
    
    CRITICAL: This returns PURE BYTES - never decode or encode!
    
    Args:
        sender (str): Username
        chunk_data (bytes): Binary file chunk
        chunk_num (int): Chunk sequence number
    
    Returns:
        bytes: Formatted message with binary data
    """
    # Create header as bytes
    header = f"{MSG_TYPE_FILE_CHUNK}|{sender}|{chunk_num}|".encode('utf-8')
    
    # Add chunk size for validation
    size_bytes = len(chunk_data).to_bytes(4, 'big')
    
    # Delimiter as bytes
    delimiter = MSG_DELIMITER.encode('utf-8')
    
    # Assemble: HEADER + SIZE + DATA + DELIMITER
    return header + size_bytes + chunk_data + delimiter


def create_file_complete_message(sender: str, filename: str, file_hash: str) -> str:
    """
    Create file transfer complete message.
    
    Args:
        sender (str): Username
        filename (str): Filename
        file_hash (str): MD5 hash for verification
    
    Returns:
        str: Formatted message
    """
    content = f"{filename}|{file_hash}"
    return create_message(MSG_TYPE_FILE_COMPLETE, sender, content)


def create_buzz_message(sender: str) -> str:
    """
    Create a buzz notification message.
    
    Args:
        sender (str): Username who sent the buzz
    
    Returns:
        str: Formatted buzz message
    """
    return create_message(MSG_TYPE_BUZZ, sender)


def create_auth_message(username: str, password: str) -> str:
    """
    Create an authentication request message.
    
    Args:
        username (str): Username
        password (str): Password
    
    Returns:
        str: Formatted authentication message
    """
    # Use JSON for auth data
    auth_data = json.dumps({"username": username, "password": password})
    return create_message(MSG_TYPE_AUTH, username, auth_data)


def create_user_list_message(users: list) -> str:
    """
    Create a user list message.
    
    Args:
        users (list): List of online usernames or user data dicts
    
    Returns:
        str: Formatted user list message
    """
    user_json = json.dumps(users)
    return create_message(MSG_TYPE_USER_LIST, "SERVER", user_json)


def create_error_message(error_text: str) -> str:
    """
    Create an error message.
    
    Args:
        error_text (str): Error description
    
    Returns:
        str: Formatted error message
    """
    return create_message(MSG_TYPE_ERROR, "SERVER", error_text)


def create_typing_message(username: str, is_typing: bool) -> str:
    """
    Create typing indicator message.
    
    Args:
        username (str): User who is typing
        is_typing (bool): True for start, False for stop
    
    Returns:
        str: Formatted message
    """
    msg_type = MSG_TYPE_TYPING_START if is_typing else MSG_TYPE_TYPING_STOP
    return create_message(msg_type, username, "")


def create_status_message(username: str, status: str) -> str:
    """
    Create user status change message.
    
    Args:
        username (str): User changing status
        status (str): New status (online, busy, offline)
    
    Returns:
        str: Formatted message
    """
    return create_message(MSG_TYPE_STATUS_CHANGE, username, status)


def create_reconnect_message(username: str, session_id: str) -> str:
    """
    Create reconnect request message.
    
    Args:
        username (str): User attempting to reconnect
        session_id (str): Previous session identifier
    
    Returns:
        str: Formatted message
    """
    data = json.dumps({"username": username, "session_id": session_id})
    return create_message(MSG_TYPE_RECONNECT, username, data)


def create_session_message(session_id: str) -> str:
    """
    Create session ID message.
    
    Args:
        session_id (str): Session identifier
    
    Returns:
        str: Formatted message
    """
    return create_message(MSG_TYPE_SESSION_ID, "SERVER", session_id)


# ==================== MESSAGE PARSING ====================

def parse_message(raw_message: str) -> dict:
    """
    Parse a protocol message into its components.
    
    Args:
        raw_message (str): Raw message string
    
    Returns:
        dict: Parsed message with keys: type, sender, content
        None: If parsing fails
    
    Example:
        >>> msg = "TEXT|alice|Hello!<END>"
        >>> parsed = parse_message(msg)
        >>> print(parsed)
        {'type': 'TEXT', 'sender': 'alice', 'content': 'Hello!'}
    """
    try:
        # Remove delimiter
        if raw_message.endswith(MSG_DELIMITER):
            raw_message = raw_message[:-len(MSG_DELIMITER)]
        
        # Split by pipe delimiter
        parts = raw_message.split('|', 2)  # Split into max 3 parts
        
        if len(parts) < 2:
            return None
        
        msg_type = parts[0]
        sender = parts[1]
        content = parts[2] if len(parts) > 2 else ""
        
        return {
            'type': msg_type,
            'sender': sender,
            'content': content
        }
    
    except Exception as e:
        print(f"Error parsing message: {e}")
        return None


def parse_file_message(content: str) -> dict:
    """
    Parse file message content.
    
    Args:
        content (str): Content from file message
    
    Returns:
        dict: Parsed file info with keys: filename, filesize
        None: If parsing fails
    """
    try:
        parts = content.split('|')
        if len(parts) != 2:
            return None
        
        return {
            'filename': parts[0],
            'filesize': int(parts[1])
        }
    except:
        return None


def parse_auth_message(content: str) -> dict:
    """
    Parse authentication message content.
    
    Args:
        content (str): JSON string with auth data
    
    Returns:
        dict: Parsed auth data with keys: username, password
        None: If parsing fails
    """
    try:
        return json.loads(content)
    except:
        return None


def parse_user_list(content: str) -> list:
    """
    Parse user list message content.
    
    Args:
        content (str): JSON string with user list
    
    Returns:
        list: List of usernames
        Empty list: If parsing fails
    """
    try:
        return json.loads(content)
    except:
        return []


# ==================== MESSAGE VALIDATION ====================

def validate_message(parsed_msg: dict) -> bool:
    """
    Validate a parsed message structure.
    
    Args:
        parsed_msg (dict): Parsed message dictionary
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not parsed_msg:
        return False
    
    # Check required keys
    required_keys = ['type', 'sender']
    if not all(key in parsed_msg for key in required_keys):
        return False
    
    # Check message type is valid
    valid_types = [
        MSG_TYPE_TEXT, MSG_TYPE_FILE, MSG_TYPE_BUZZ,
        MSG_TYPE_USER_JOIN, MSG_TYPE_USER_LEAVE, MSG_TYPE_USER_LIST,
        MSG_TYPE_AUTH, MSG_TYPE_AUTH_OK, MSG_TYPE_AUTH_FAIL,
        MSG_TYPE_ERROR, MSG_TYPE_FILE_CHUNK
    ]
    
    if parsed_msg['type'] not in valid_types:
        return False
    
    return True


def validate_username(username: str) -> tuple:
    """
    Validate username format.
    
    Args:
        username (str): Username to validate
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    
    Rules:
        - 3-20 characters
        - Alphanumeric and underscores only
        - Cannot start with number
    """
    if not username:
        return False, "Username cannot be empty"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 20:
        return False, "Username must be at most 20 characters"
    
    if username[0].isdigit():
        return False, "Username cannot start with a number"
    
    if not username.replace('_', '').isalnum():
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, ""


# ==================== MESSAGE HANDLING ====================

class MessageBuffer:
    """
    Buffer for handling incomplete messages from TCP stream.
    
    TCP is a stream protocol, so messages may arrive in chunks.
    This class accumulates data until complete messages are received.
    """
    
    def __init__(self):
        """Initialize empty buffer."""
        self.buffer = ""
    
    def add_data(self, data: str):
        """
        Add received data to buffer.
        
        Args:
            data (str): Newly received data
        """
        self.buffer += data
    
    def get_messages(self) -> list:
        """
        Extract complete messages from buffer.
        
        Returns:
            list: List of complete message strings
        """
        messages = []
        
        while MSG_DELIMITER in self.buffer:
            # Find delimiter
            delimiter_pos = self.buffer.index(MSG_DELIMITER)
            
            # Extract message
            message = self.buffer[:delimiter_pos + len(MSG_DELIMITER)]
            messages.append(message)
            
            # Remove from buffer
            self.buffer = self.buffer[delimiter_pos + len(MSG_DELIMITER):]
        
        return messages
    
    def clear(self):
        """Clear the buffer."""
        self.buffer = ""
    
    def has_data(self) -> bool:
        """Check if buffer contains data."""
        return len(self.buffer) > 0


# ==================== TESTING ====================

def test_protocol():
    """Test protocol functions."""
    print("=" * 50)
    print("Protocol Module Test")
    print("=" * 50)
    
    # Test message creation and parsing
    test_cases = [
        ("TEXT", "alice", "Hello, World!"),
        ("BUZZ", "bob", ""),
        ("FILE", "charlie", "document.pdf|1024"),
        ("USER_JOIN", "SERVER", "alice"),
    ]
    
    for msg_type, sender, content in test_cases:
        # Create message
        message = create_message(msg_type, sender, content)
        print(f"\nCreated: {message[:50]}...")
        
        # Parse message
        parsed = parse_message(message)
        print(f"Parsed: {parsed}")
        
        # Validate
        is_valid = validate_message(parsed)
        print(f"Valid: {'✓' if is_valid else '✗'}")
        
        # Verify content matches
        content_match = (
            parsed['type'] == msg_type and
            parsed['sender'] == sender and
            parsed['content'] == content
        )
        print(f"Content Match: {'✓' if content_match else '✗'}")
    
    # Test username validation
    print("\n" + "=" * 50)
    print("Username Validation Test")
    print("=" * 50)
    
    test_usernames = [
        "alice",       # Valid
        "bob123",      # Valid
        "user_name",   # Valid
        "ab",          # Too short
        "123user",     # Starts with number
        "user@name",   # Invalid character
        "a" * 25,      # Too long
    ]
    
    for username in test_usernames:
        is_valid, error = validate_username(username)
        status = "✓ VALID" if is_valid else f"✗ INVALID: {error}"
        print(f"{username:20s} → {status}")
    
    # Test message buffer
    print("\n" + "=" * 50)
    print("Message Buffer Test")
    print("=" * 50)
    
    buffer = MessageBuffer()
    
    # Simulate fragmented messages
    buffer.add_data("TEXT|alice|Hello")
    print(f"Added fragment 1, messages: {len(buffer.get_messages())}")
    
    buffer.add_data(", World!<END>")
    messages = buffer.get_messages()
    print(f"Added fragment 2, messages: {len(messages)}")
    print(f"Message: {messages[0] if messages else 'None'}")
    
    # Test multiple messages at once
    buffer.add_data("TEXT|bob|Hi<END>TEXT|charlie|Hey<END>")
    messages = buffer.get_messages()
    print(f"\nAdded 2 complete messages, extracted: {len(messages)}")
    for i, msg in enumerate(messages, 1):
        print(f"  Message {i}: {msg[:30]}...")
    
    print("\n" + "=" * 50)
    print("✓ All tests completed")
    print("=" * 50)


if __name__ == "__main__":
    test_protocol()