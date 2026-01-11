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
MSG_TYPE_FILE_ACK = 'FILE_ACK'
MSG_TYPE_PROGRESS = 'PROGRESS'

MSG_DELIMITER = '<END>'

# ==================== ENCRYPTION CONFIGURATION ====================

ENCRYPTION_METHOD = 'XOR'
XOR_KEY = 0xAB
CAESAR_SHIFT = 13

# ==================== FILE TRANSFER CONFIGURATION ====================

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
CHUNK_SIZE = 8192  # 8KB chunks for smooth progress
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB

ALLOWED_EXTENSIONS = []

# Downloads folder
DOWNLOADS_FOLDER = 'downloads'
FILE_TRANSFER_LOG = 'file_transfers.log'

# ==================== GUI CONFIGURATION - DISCORD DARK THEME ====================

WINDOW_TITLE = "Chat Application - Discord Dark"
WINDOW_WIDTH = 900
WINDOW_HEIGHT = 650
WINDOW_MIN_WIDTH = 700
WINDOW_MIN_HEIGHT = 500

# Discord Dark Theme Colors
BG_COLOR = "#36393f"              # Main background (Dark gray)
SIDEBAR_COLOR = "#2f3136"         # Sidebar background (Darker)
CHAT_BG_COLOR = "#36393f"         # Chat area background
INPUT_BG_COLOR = "#40444b"        # Input field background
TEXT_COLOR = "#ffffff"            # Primary text (White)
TEXT_SECONDARY = "#b9bbbe"        # Secondary text (Light gray)
ACCENT_COLOR = "#5865f2"          # Discord Blue
BUTTON_COLOR = "#5865f2"          # Primary buttons
BUTTON_HOVER = "#4752c4"          # Button hover
BUZZ_COLOR = "#ed4245"            # Buzz/Alert (Red)
SUCCESS_COLOR = "#3ba55d"         # Success messages (Green)
WARNING_COLOR = "#faa81a"         # Warnings (Orange)
ERROR_COLOR = "#ed4245"           # Errors (Red)

# Message Colors
MSG_COLOR_SELF = "#3ba55d"        # Green for own messages
MSG_COLOR_OTHERS = "#faa81a"      # Orange for other users
MSG_COLOR_SERVER = "#5865f2"      # Blue for server messages
MSG_COLOR_BUZZ = "#ed4245"        # Red for buzz
MSG_COLOR_FILE = "#00b0f4"        # Cyan for file transfers

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
    'test': 'test'
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
    Theme: Discord Dark
    Downloads: {DOWNLOADS_FOLDER}/
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