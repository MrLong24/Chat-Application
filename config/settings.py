# ==================== SERVER CONFIGURATION ====================

TCP_HOST = '0.0.0.0'
TCP_PORT = 5000

UDP_HOST = '0.0.0.0'
UDP_PORT = 5001

MAX_CLIENTS = 50
BUFFER_SIZE = 4096
FILE_BUFFER_SIZE = 8192

# ==================== CLIENT CONFIGURATION ====================

DEFAULT_SERVER_IP = '127.0.0.1'
DEFAULT_TCP_PORT = 5000
DEFAULT_UDP_PORT = 5001

CONNECTION_TIMEOUT = 10
RECONNECT_ATTEMPTS = 3
RECONNECT_DELAY = 2

# ==================== PROTOCOL CONFIGURATION ====================

# Core message types
MSG_TYPE_TEXT = 'TEXT'
MSG_TYPE_FILE = 'FILE'
MSG_TYPE_FILE_CHUNK = 'CHUNK'
MSG_TYPE_FILE_COMPLETE = 'FILE_COMPLETE'
MSG_TYPE_BUZZ = 'BUZZ'
MSG_TYPE_USER_JOIN = 'USER_JOIN'
MSG_TYPE_USER_LEAVE = 'USER_LEAVE'
MSG_TYPE_USER_LIST = 'USER_LIST'
MSG_TYPE_AUTH = 'AUTH'
MSG_TYPE_AUTH_OK = 'AUTH_OK'
MSG_TYPE_AUTH_FAIL = 'AUTH_FAIL'
MSG_TYPE_ERROR = 'ERROR'

# TIER 1 FEATURE: Typing indicators (server-relayed)
MSG_TYPE_TYPING_START = 'TYPING_START'
MSG_TYPE_TYPING_STOP = 'TYPING_STOP'

# TIER 1 FEATURE: User status (server-authoritative)
MSG_TYPE_STATUS_CHANGE = 'STATUS_CHANGE'
MSG_TYPE_STATUS_UPDATE = 'STATUS_UPDATE'

# TIER 1 FEATURE: Message delivery tracking
MSG_TYPE_MESSAGE_SENT = 'MESSAGE_SENT'
MSG_TYPE_MESSAGE_DELIVERED = 'MSG_DELIVERED'
MSG_TYPE_MESSAGE_READ = 'MSG_READ'
MSG_TYPE_DELIVERY_ACK = 'DELIVERY_ACK'
MSG_TYPE_READ_ACK = 'READ_ACK'

# TIER 1 FEATURE: Reconnect & session management
MSG_TYPE_RECONNECT = 'RECONNECT'
MSG_TYPE_SESSION_ID = 'SESSION_ID'
MSG_TYPE_HEARTBEAT = 'HEARTBEAT'

# ==================== TIER 2: ADVANCED FILE TRANSFER ====================

# File transfer protocol
MSG_TYPE_FILE_OFFER = 'FILE_OFFER'       # Sender → Receiver: Offer file
MSG_TYPE_FILE_ACCEPT = 'FILE_ACCEPT'     # Receiver → Sender: Accept download
MSG_TYPE_FILE_REJECT = 'FILE_REJECT'     # Receiver → Sender: Reject download
MSG_TYPE_FILE_DATA = 'FILE_DATA'         # Sender → Receiver: Chunk data
MSG_TYPE_FILE_PAUSE = 'FILE_PAUSE'       # Either: Pause transfer
MSG_TYPE_FILE_RESUME = 'FILE_RESUME'     # Either: Resume transfer
MSG_TYPE_FILE_CANCEL = 'FILE_CANCEL'     # Either: Cancel transfer
MSG_TYPE_FILE_ACK = 'FILE_ACK'           # Receiver → Sender: Chunk received

# File transfer states
FILE_STATE_OFFERED = 'offered'           # File offered, waiting for response
FILE_STATE_ACCEPTED = 'accepted'         # Receiver accepted
FILE_STATE_REJECTED = 'rejected'         # Receiver rejected
FILE_STATE_TRANSFERRING = 'transferring' # Active transfer
FILE_STATE_PAUSED = 'paused'             # Paused
FILE_STATE_COMPLETED = 'completed'       # Successfully completed
FILE_STATE_CANCELLED = 'cancelled'       # Cancelled by user
FILE_STATE_ERROR = 'error'               # Error occurred

MSG_DELIMITER = '<END>'

# User Status Values (server-authoritative)
STATUS_ONLINE = 'online'
STATUS_BUSY = 'busy'
STATUS_OFFLINE = 'offline'

# Typing indicator settings
TYPING_TIMEOUT = 3
TYPING_DEBOUNCE = 0.5

# Message delivery tracking
MESSAGE_ID_START = 1000
MESSAGE_TIMEOUT = 30

# ==================== ENCRYPTION CONFIGURATION ====================

ENCRYPTION_METHOD = 'XOR'
XOR_KEY = 0xAB
CAESAR_SHIFT = 13

# ==================== FILE TRANSFER CONFIGURATION ====================

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
CHUNK_SIZE = 8192  # 8KB chunks
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB

# TIER 2: File transfer settings
FILE_CHUNK_SIZE = 8192               # 8KB per chunk
FILE_TRANSFER_TIMEOUT = 300          # 5 minutes timeout
FILE_MAX_CONCURRENT = 10             # Max concurrent transfers per user
FILE_ACK_FREQUENCY = 10              # Send ACK every N chunks
FILE_RETRY_ATTEMPTS = 3              # Retry failed chunks
FILE_RETRY_DELAY = 1                 # Seconds between retries

ALLOWED_EXTENSIONS = []

DOWNLOADS_FOLDER = 'downloads'
FILE_TRANSFER_LOG = 'file_transfers.log'

# ==================== GUI CONFIGURATION - DISCORD DARK THEME ====================

WINDOW_TITLE = "Chat Application - Discord Dark"
WINDOW_WIDTH = 900
WINDOW_HEIGHT = 650
WINDOW_MIN_WIDTH = 700
WINDOW_MIN_HEIGHT = 500

# Discord Dark Theme Colors
BG_COLOR = "#36393f"
SIDEBAR_COLOR = "#2f3136"
CHAT_BG_COLOR = "#36393f"
INPUT_BG_COLOR = "#40444b"
TEXT_COLOR = "#ffffff"
TEXT_SECONDARY = "#b9bbbe"
ACCENT_COLOR = "#5865f2"
BUTTON_COLOR = "#5865f2"
BUTTON_HOVER = "#4752c4"
BUZZ_COLOR = "#ed4245"
SUCCESS_COLOR = "#3ba55d"
WARNING_COLOR = "#faa81a"
ERROR_COLOR = "#ed4245"

# Message Colors
MSG_COLOR_SELF = "#3ba55d"
MSG_COLOR_OTHERS = "#faa81a"
MSG_COLOR_SERVER = "#5865f2"
MSG_COLOR_BUZZ = "#ed4245"
MSG_COLOR_FILE = "#00b0f4"

# Font Settings
FONT_FAMILY = "Segoe UI"
FONT_SIZE_NORMAL = 10
FONT_SIZE_LARGE = 12
FONT_SIZE_SMALL = 9
FONT_SIZE_TITLE = 16

# ==================== LOGGING CONFIGURATION ====================

LOG_LEVEL = 'INFO'
LOG_TO_FILE = True
LOG_FILE_SERVER = 'logs/server.log'
LOG_FILE_CLIENT = 'logs/client.log'
LOG_MAX_SIZE = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

# ==================== AUTHENTICATION CONFIGURATION ====================

USER_DATABASE = {
    'alice': 'password123',
    'bob': 'securepass',
    'charlie': 'mypass',
    'demo': 'demo',
    'test': 'test',
    'long': '123',
    'phi': '123',
    'duc': '123'
}

SESSION_TIMEOUT = 3600
MAX_LOGIN_ATTEMPTS = 3

# ==================== BUZZ FEATURE CONFIGURATION ====================

BUZZ_DURATION = 500
BUZZ_SHAKE_DISTANCE = 10
BUZZ_SHAKE_INTERVAL = 50
BUZZ_COOLDOWN = 5

# ==================== HELPER FUNCTIONS ====================

def get_config_summary():
    """Returns formatted configuration summary."""
    return f"""
    ========== Configuration Summary ==========
    TCP Server: {TCP_HOST}:{TCP_PORT}
    UDP Server: {UDP_HOST}:{UDP_PORT}
    Max Clients: {MAX_CLIENTS}
    Buffer Size: {BUFFER_SIZE} bytes
    Encryption: {ENCRYPTION_METHOD}
    Max File Size: {MAX_FILE_SIZE / (1024*1024):.0f} MB
    File Chunk Size: {FILE_CHUNK_SIZE} bytes
    Max Concurrent Transfers: {FILE_MAX_CONCURRENT}
    Theme: Discord Dark
    Downloads: {DOWNLOADS_FOLDER}/
    Features: Chat, Typing, Status, File Transfer (Tier 2)
    ===========================================
    """

def validate_config():
    """Validates configuration settings."""
    if not (1024 <= TCP_PORT <= 65535):
        raise ValueError(f"Invalid TCP_PORT: {TCP_PORT}")
    
    if not (1024 <= UDP_PORT <= 65535):
        raise ValueError(f"Invalid UDP_PORT: {UDP_PORT}")
    
    valid_encryption = ['XOR', 'CAESAR', 'NONE']
    if ENCRYPTION_METHOD not in valid_encryption:
        raise ValueError(f"Invalid ENCRYPTION_METHOD: {ENCRYPTION_METHOD}")
    
    if BUFFER_SIZE < 1024:
        raise ValueError(f"BUFFER_SIZE too small: {BUFFER_SIZE}")
    
    print("✓ Configuration validation passed")

if __name__ != "__main__":
    try:
        validate_config()
    except ValueError as e:
        print(f"⚠ Configuration Error: {e}")