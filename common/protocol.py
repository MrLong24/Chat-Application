import json
import sys
import os
import time
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    MSG_TYPE_DELIVERY_ACK, MSG_TYPE_FILE_COMPLETE, MSG_TYPE_MESSAGE_SENT, 
    MSG_TYPE_READ_ACK, MSG_TYPE_RECONNECT, MSG_TYPE_SESSION_ID, 
    MSG_TYPE_STATUS_CHANGE, MSG_TYPE_TEXT, MSG_TYPE_FILE, MSG_TYPE_BUZZ, 
    MSG_TYPE_TYPING_START, MSG_TYPE_TYPING_STOP,
    MSG_TYPE_USER_JOIN, MSG_TYPE_USER_LEAVE, MSG_TYPE_USER_LIST,
    MSG_TYPE_AUTH, MSG_TYPE_AUTH_OK, MSG_TYPE_AUTH_FAIL,
    MSG_TYPE_ERROR, MSG_DELIMITER, MSG_TYPE_FILE_CHUNK,
    # TIER 2: File transfer protocol
    MSG_TYPE_FILE_OFFER, MSG_TYPE_FILE_ACCEPT, MSG_TYPE_FILE_REJECT,
    MSG_TYPE_FILE_DATA, MSG_TYPE_FILE_PAUSE, MSG_TYPE_FILE_RESUME,
    MSG_TYPE_FILE_CANCEL, MSG_TYPE_FILE_ACK
)

# ==================== MESSAGE CREATION ====================

def create_message(msg_type: str, sender: str, content: str = "") -> str:
    """Create a formatted protocol message."""
    return f"{msg_type}|{sender}|{content}{MSG_DELIMITER}"


def create_text_message(sender: str, text: str) -> str:
    """Create a text message."""
    return create_message(MSG_TYPE_TEXT, sender, text)


def create_file_message(sender: str, filename: str, filesize: int) -> str:
    """Create a file transfer initialization message (legacy)."""
    content = f"{filename}|{filesize}"
    return create_message(MSG_TYPE_FILE, sender, content)


def create_file_chunk_message(sender: str, chunk_data: bytes, chunk_num: int) -> bytes:
    """Create a file chunk message with binary data (legacy)."""
    header = f"{MSG_TYPE_FILE_CHUNK}|{sender}|{chunk_num}|".encode('utf-8')
    size_bytes = len(chunk_data).to_bytes(4, 'big')
    delimiter = MSG_DELIMITER.encode('utf-8')
    return header + size_bytes + chunk_data + delimiter


def create_file_complete_message(sender: str, filename: str, file_hash: str) -> str:
    """Create file transfer complete message (legacy)."""
    content = f"{filename}|{file_hash}"
    return create_message(MSG_TYPE_FILE_COMPLETE, sender, content)


def create_buzz_message(sender: str) -> str:
    """Create a buzz notification message."""
    return create_message(MSG_TYPE_BUZZ, sender)


def create_auth_message(username: str, password: str) -> str:
    """Create an authentication request message."""
    auth_data = json.dumps({"username": username, "password": password})
    return create_message(MSG_TYPE_AUTH, username, auth_data)


def create_user_list_message(users: list) -> str:
    """Create a user list message."""
    user_json = json.dumps(users)
    return create_message(MSG_TYPE_USER_LIST, "SERVER", user_json)


def create_error_message(error_text: str) -> str:
    """Create an error message."""
    return create_message(MSG_TYPE_ERROR, "SERVER", error_text)


def create_typing_message(username: str, is_typing: bool) -> str:
    """Create typing indicator message."""
    msg_type = MSG_TYPE_TYPING_START if is_typing else MSG_TYPE_TYPING_STOP
    return create_message(msg_type, username, "")


def create_status_message(username: str, status: str) -> str:
    """Create user status change message."""
    return create_message(MSG_TYPE_STATUS_CHANGE, username, status)


def create_reconnect_message(username: str, session_id: str) -> str:
    """Create reconnect request message."""
    data = json.dumps({"username": username, "session_id": session_id})
    return create_message(MSG_TYPE_RECONNECT, username, data)


def create_session_message(session_id: str) -> str:
    """Create session ID message."""
    return create_message(MSG_TYPE_SESSION_ID, "SERVER", session_id)


# ==================== TIER 1: MESSAGE DELIVERY TRACKING ====================

def create_text_with_id(sender: str, text: str, msg_id: int, timestamp: str) -> str:
    """Create text message with ID and timestamp for delivery tracking."""
    content = json.dumps({
        'text': text,
        'msg_id': msg_id,
        'timestamp': timestamp
    })
    return create_message(MSG_TYPE_MESSAGE_SENT, sender, content)


def create_delivered_ack(msg_id: int, recipient: str) -> str:
    """Create delivery acknowledgment."""
    content = json.dumps({'msg_id': msg_id, 'recipient': recipient})
    return create_message(MSG_TYPE_DELIVERY_ACK, "SERVER", content)


def create_read_ack(msg_id: int, reader: str) -> str:
    """Create read acknowledgment."""
    content = json.dumps({'msg_id': msg_id, 'reader': reader})
    return create_message(MSG_TYPE_READ_ACK, reader, content)


def parse_message_with_id(content: str) -> dict:
    """Parse message content with ID and timestamp."""
    try:
        return json.loads(content)
    except:
        return {'text': content, 'msg_id': 0, 'timestamp': ''}


# ==================== TIER 2: FILE TRANSFER PROTOCOL ====================

def create_file_offer_message(sender: str, file_id: str, filename: str, 
                              filesize: int, checksum: str = "") -> str:
    """
    Create FILE_OFFER message.
    
    Args:
        sender: Username offering the file
        file_id: Unique file transfer ID (UUID)
        filename: Name of file
        filesize: Size in bytes
        checksum: Optional MD5 checksum
    
    Returns:
        Formatted FILE_OFFER message
    """
    offer_data = {
        'file_id': file_id,
        'filename': filename,
        'filesize': filesize,
        'checksum': checksum,
        'timestamp': datetime.now().isoformat()
    }
    return create_message(MSG_TYPE_FILE_OFFER, sender, json.dumps(offer_data))


def create_file_accept_message(sender: str, file_id: str) -> str:
    """
    Create FILE_ACCEPT message.
    
    Args:
        sender: Username accepting the file
        file_id: File transfer ID being accepted
    
    Returns:
        Formatted FILE_ACCEPT message
    """
    accept_data = {'file_id': file_id}
    return create_message(MSG_TYPE_FILE_ACCEPT, sender, json.dumps(accept_data))


def create_file_reject_message(sender: str, file_id: str, reason: str = "") -> str:
    """
    Create FILE_REJECT message.
    
    Args:
        sender: Username rejecting the file
        file_id: File transfer ID being rejected
        reason: Optional rejection reason
    
    Returns:
        Formatted FILE_REJECT message
    """
    reject_data = {'file_id': file_id, 'reason': reason}
    return create_message(MSG_TYPE_FILE_REJECT, sender, json.dumps(reject_data))


def create_file_data_message(sender: str, file_id: str, offset: int, 
                             chunk_data: bytes) -> bytes:
    """
    Create FILE_DATA message with binary chunk.
    
    CRITICAL: Returns PURE BYTES containing binary data.
    
    Args:
        sender: Username sending the chunk
        file_id: File transfer ID
        offset: Byte offset of this chunk
        chunk_data: Binary data chunk
    
    Returns:
        bytes: Complete message with binary data
    """
    # Create JSON header with metadata
    header_data = {
        'file_id': file_id,
        'offset': offset,
        'size': len(chunk_data)
    }
    
    # Format: FILE_DATA|sender|{json_metadata}|<binary_data><END>
    header_text = f"{MSG_TYPE_FILE_DATA}|{sender}|{json.dumps(header_data)}|"
    header_bytes = header_text.encode('utf-8')
    
    delimiter_bytes = MSG_DELIMITER.encode('utf-8')
    
    # Assemble: HEADER + BINARY_DATA + DELIMITER
    return header_bytes + chunk_data + delimiter_bytes


def create_file_pause_message(sender: str, file_id: str, offset: int) -> str:
    """
    Create FILE_PAUSE message.
    
    Args:
        sender: Username pausing the transfer
        file_id: File transfer ID
        offset: Current byte offset when paused
    
    Returns:
        Formatted FILE_PAUSE message
    """
    pause_data = {'file_id': file_id, 'offset': offset}
    return create_message(MSG_TYPE_FILE_PAUSE, sender, json.dumps(pause_data))


def create_file_resume_message(sender: str, file_id: str, offset: int) -> str:
    """
    Create FILE_RESUME message.
    
    Args:
        sender: Username resuming the transfer
        file_id: File transfer ID
        offset: Byte offset to resume from
    
    Returns:
        Formatted FILE_RESUME message
    """
    resume_data = {'file_id': file_id, 'offset': offset}
    return create_message(MSG_TYPE_FILE_RESUME, sender, json.dumps(resume_data))


def create_file_cancel_message(sender: str, file_id: str, reason: str = "") -> str:
    """
    Create FILE_CANCEL message.
    
    Args:
        sender: Username cancelling the transfer
        file_id: File transfer ID
        reason: Optional cancellation reason
    
    Returns:
        Formatted FILE_CANCEL message
    """
    cancel_data = {'file_id': file_id, 'reason': reason}
    return create_message(MSG_TYPE_FILE_CANCEL, sender, json.dumps(cancel_data))


def create_file_ack_message(sender: str, file_id: str, offset: int) -> str:
    """
    Create FILE_ACK message (acknowledge received chunk).
    
    Args:
        sender: Username acknowledging
        file_id: File transfer ID
        offset: Byte offset successfully received up to
    
    Returns:
        Formatted FILE_ACK message
    """
    ack_data = {'file_id': file_id, 'offset': offset}
    return create_message(MSG_TYPE_FILE_ACK, sender, json.dumps(ack_data))


def create_file_complete_message_v2(sender: str, file_id: str, checksum: str = "") -> str:
    """
    Create FILE_COMPLETE message (Tier 2 version).
    
    Args:
        sender: Username completing transfer
        file_id: File transfer ID
        checksum: Optional verification checksum
    
    Returns:
        Formatted FILE_COMPLETE message
    """
    complete_data = {'file_id': file_id, 'checksum': checksum}
    return create_message(MSG_TYPE_FILE_COMPLETE, sender, json.dumps(complete_data))


def parse_file_offer(content: str) -> dict:
    """
    Parse FILE_OFFER message content.
    
    Returns:
        dict with keys: file_id, filename, filesize, checksum, timestamp
    """
    try:
        return json.loads(content)
    except:
        return {}


def parse_file_data_header(raw_message: str) -> dict:
    """
    Parse FILE_DATA message header (before binary data).
    
    Args:
        raw_message: Raw message string (may contain binary)
    
    Returns:
        dict with keys: file_id, offset, size
    """
    try:
        # Split by delimiter to isolate header
        parts = raw_message.split('|', 2)
        if len(parts) >= 3:
            metadata_json = parts[2].split(MSG_DELIMITER)[0]
            return json.loads(metadata_json)
    except:
        pass
    return {}


# ==================== MESSAGE PARSING ====================

def parse_message(raw_message: str) -> dict:
    """
    Parse a protocol message into its components.
    
    Returns:
        dict: Parsed message with keys: type, sender, content
        None: If parsing fails
    """
    try:
        if raw_message.endswith(MSG_DELIMITER):
            raw_message = raw_message[:-len(MSG_DELIMITER)]
        
        parts = raw_message.split('|', 2)
        
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
    """Parse file message content (legacy)."""
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
    """Parse authentication message content."""
    try:
        return json.loads(content)
    except:
        return None


def parse_user_list(content: str) -> list:
    """Parse user list message content."""
    try:
        return json.loads(content)
    except:
        return []


# ==================== MESSAGE VALIDATION ====================

def validate_message(parsed_msg: dict) -> bool:
    """Validate a parsed message structure."""
    if not parsed_msg:
        return False
    
    required_keys = ['type', 'sender']
    if not all(key in parsed_msg for key in required_keys):
        return False
    
    valid_types = [
        MSG_TYPE_TEXT, MSG_TYPE_FILE, MSG_TYPE_BUZZ,
        MSG_TYPE_USER_JOIN, MSG_TYPE_USER_LEAVE, MSG_TYPE_USER_LIST,
        MSG_TYPE_AUTH, MSG_TYPE_AUTH_OK, MSG_TYPE_AUTH_FAIL,
        MSG_TYPE_ERROR, MSG_TYPE_FILE_CHUNK,
        # Tier 2 types
        MSG_TYPE_FILE_OFFER, MSG_TYPE_FILE_ACCEPT, MSG_TYPE_FILE_REJECT,
        MSG_TYPE_FILE_DATA, MSG_TYPE_FILE_PAUSE, MSG_TYPE_FILE_RESUME,
        MSG_TYPE_FILE_CANCEL, MSG_TYPE_FILE_ACK, MSG_TYPE_FILE_COMPLETE
    ]
    
    if parsed_msg['type'] not in valid_types:
        return False
    
    return True


def validate_username(username: str) -> tuple:
    """Validate username format."""
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
    """Buffer for handling incomplete messages from TCP stream."""
    
    def __init__(self):
        self.buffer = ""
    
    def add_data(self, data: str):
        """Add received data to buffer."""
        self.buffer += data
    
    def get_messages(self) -> list:
        """Extract complete messages from buffer."""
        messages = []
        
        while MSG_DELIMITER in self.buffer:
            delimiter_pos = self.buffer.index(MSG_DELIMITER)
            message = self.buffer[:delimiter_pos + len(MSG_DELIMITER)]
            messages.append(message)
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
    print("=" * 60)
    print("Protocol Module Test - Tier 2")
    print("=" * 60)
    
    # Test Tier 2 file transfer messages
    import uuid
    
    file_id = str(uuid.uuid4())
    filename = "test_document.pdf"
    filesize = 1024 * 1024  # 1MB
    
    print("\n--- File Transfer Protocol Tests ---")
    
    # Test FILE_OFFER
    offer_msg = create_file_offer_message("alice", file_id, filename, filesize, "abc123")
    print(f"\nFILE_OFFER: {offer_msg[:80]}...")
    parsed = parse_message(offer_msg)
    offer_data = parse_file_offer(parsed['content'])
    print(f"Parsed offer: {offer_data}")
    
    # Test FILE_ACCEPT
    accept_msg = create_file_accept_message("bob", file_id)
    print(f"\nFILE_ACCEPT: {accept_msg[:80]}...")
    
    # Test FILE_DATA
    chunk = b"Binary data chunk here..."
    data_msg = create_file_data_message("alice", file_id, 0, chunk)
    print(f"\nFILE_DATA: {len(data_msg)} bytes (binary)")
    
    # Test FILE_PAUSE
    pause_msg = create_file_pause_message("bob", file_id, 4096)
    print(f"\nFILE_PAUSE: {pause_msg[:80]}...")
    
    # Test FILE_RESUME
    resume_msg = create_file_resume_message("bob", file_id, 4096)
    print(f"\nFILE_RESUME: {resume_msg[:80]}...")
    
    # Test FILE_CANCEL
    cancel_msg = create_file_cancel_message("alice", file_id, "User cancelled")
    print(f"\nFILE_CANCEL: {cancel_msg[:80]}...")
    
    # Test FILE_COMPLETE
    complete_msg = create_file_complete_message_v2("alice", file_id, "def456")
    print(f"\nFILE_COMPLETE: {complete_msg[:80]}...")
    
    print("\n" + "=" * 60)
    print("✓ Tier 2 Protocol Tests Completed")
    print("=" * 60)


if __name__ == "__main__":
    test_protocol()