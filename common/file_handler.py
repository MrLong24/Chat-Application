import os
import sys
import hashlib
from typing import Tuple, Optional, Callable

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    CHUNK_SIZE, MAX_FILE_SIZE, ALLOWED_EXTENSIONS,
    FILE_BUFFER_SIZE, DOWNLOADS_FOLDER, LARGE_FILE_THRESHOLD
)


# ==================== FILE VALIDATION ====================

def validate_file(filepath: str) -> Tuple[bool, str]:
    """
    Validate a file for transfer.
    
    Args:
        filepath (str): Path to file
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not os.path.exists(filepath):
        return False, "File does not exist"
    
    if not os.path.isfile(filepath):
        return False, "Path is not a file"
    
    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        max_mb = MAX_FILE_SIZE / (1024 * 1024)
        return False, f"File too large (max {max_mb:.0f} MB)"
    
    if file_size == 0:
        return False, "File is empty"
    
    if ALLOWED_EXTENSIONS:
        _, ext = os.path.splitext(filepath)
        if ext.lower() not in ALLOWED_EXTENSIONS:
            return False, f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
    
    return True, ""


def get_file_info(filepath: str) -> dict:
    """
    Get comprehensive file information.
    
    Args:
        filepath (str): Path to file
    
    Returns:
        dict: File information
    """
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    _, extension = os.path.splitext(filename)
    
    file_hash = calculate_file_hash(filepath)
    
    # Determine if this is a "large" file requiring progress bar
    is_large = filesize > LARGE_FILE_THRESHOLD
    
    return {
        'filename': filename,
        'filesize': filesize,
        'extension': extension,
        'hash': file_hash,
        'path': filepath,
        'is_large': is_large,
        'total_chunks': (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE
    }


def calculate_file_hash(filepath: str, algorithm: str = 'md5') -> str:
    """
    Calculate file hash for integrity verification.
    
    Args:
        filepath (str): Path to file
        algorithm (str): Hash algorithm
    
    Returns:
        str: Hexadecimal hash string
    """
    hash_func = hashlib.md5() if algorithm == 'md5' else hashlib.sha256()
    
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(FILE_BUFFER_SIZE)
                if not chunk:
                    break
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    except Exception as e:
        print(f"Error calculating file hash: {e}")
        return ""


# ==================== FILE READING WITH PROGRESS ====================

class FileReader:
    """
    Read file in chunks with progress tracking.
    """
    
    def __init__(self, filepath: str, chunk_size: int = CHUNK_SIZE,
                 progress_callback: Optional[Callable] = None):
        """
        Initialize file reader.
        
        Args:
            filepath (str): Path to file
            chunk_size (int): Size of each chunk
            progress_callback: Function called with (bytes_read, total_size)
        """
        self.filepath = filepath
        self.chunk_size = chunk_size
        self.progress_callback = progress_callback
        self.file_handle = None
        self.total_size = os.path.getsize(filepath)
        self.bytes_read = 0
        self.chunk_count = 0
    
    def open(self):
        """Open file for reading."""
        self.file_handle = open(self.filepath, 'rb')
        self.bytes_read = 0
        self.chunk_count = 0
    
    def read_chunk(self) -> Optional[bytes]:
        """
        Read next chunk from file.
        
        Returns:
            bytes: Chunk data, or None if end of file
        """
        if not self.file_handle:
            return None
        
        chunk = self.file_handle.read(self.chunk_size)
        
        if chunk:
            self.bytes_read += len(chunk)
            self.chunk_count += 1
            
            # Call progress callback
            if self.progress_callback:
                try:
                    self.progress_callback(self.bytes_read, self.total_size)
                except Exception as e:
                    print(f"Progress callback error: {e}")
        
        return chunk if chunk else None
    
    def get_progress(self) -> float:
        """
        Get read progress as percentage.
        
        Returns:
            float: Progress percentage (0-100)
        """
        if self.total_size == 0:
            return 100.0
        return (self.bytes_read / self.total_size) * 100
    
    def get_progress_info(self) -> dict:
        """
        Get detailed progress information.
        
        Returns:
            dict: Progress details
        """
        return {
            'bytes_read': self.bytes_read,
            'total_size': self.total_size,
            'percentage': self.get_progress(),
            'chunks_sent': self.chunk_count,
            'total_chunks': (self.total_size + self.chunk_size - 1) // self.chunk_size
        }
    
    def close(self):
        """Close file handle."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# ==================== FILE WRITING WITH PROGRESS ====================

class FileWriter:
    """
    Write received file chunks with progress tracking.
    """
    
    def __init__(self, filename: str, expected_size: int = 0,
                 progress_callback: Optional[Callable] = None):
        """
        Initialize file writer.
        
        Args:
            filename: Filename (will be saved in downloads folder)
            expected_size: Expected total file size
            progress_callback: Function called with (bytes_written, total_size)
        """
        # Ensure downloads folder exists
        if not os.path.exists(DOWNLOADS_FOLDER):
            os.makedirs(DOWNLOADS_FOLDER)
        
        # Sanitize filename and ensure uniqueness
        safe_filename = sanitize_filename(filename)
        unique_filename = ensure_unique_filename(DOWNLOADS_FOLDER, safe_filename)
        
        self.filepath = os.path.join(DOWNLOADS_FOLDER, unique_filename)
        self.filename = unique_filename
        self.progress_callback = progress_callback
        self.file_handle = None
        self.bytes_written = 0
        self.expected_size = expected_size
        self.chunk_count = 0
    
    def open(self):
        """Open file for writing."""
        self.file_handle = open(self.filepath, 'wb')
        self.bytes_written = 0
        self.chunk_count = 0
    
    def write_chunk(self, chunk: bytes):
        """
        Write chunk to file.
        
        Args:
            chunk (bytes): Data chunk to write
        """
        if not self.file_handle:
            raise IOError("File not opened for writing")
        
        self.file_handle.write(chunk)
        self.bytes_written += len(chunk)
        self.chunk_count += 1
        
        # Call progress callback
        if self.progress_callback:
            try:
                self.progress_callback(self.bytes_written, self.expected_size)
            except Exception as e:
                print(f"Progress callback error: {e}")
    
    def get_progress(self) -> float:
        """
        Get write progress as percentage.
        
        Returns:
            float: Progress percentage (0-100)
        """
        if self.expected_size == 0:
            return 0.0
        return (self.bytes_written / self.expected_size) * 100
    
    def is_complete(self) -> bool:
        """
        Check if expected number of bytes have been written.
        
        Returns:
            bool: True if complete
        """
        if self.expected_size == 0:
            return False
        return self.bytes_written >= self.expected_size
    
    def get_filepath(self) -> str:
        """Get absolute path to saved file."""
        return os.path.abspath(self.filepath)
    
    def close(self):
        """Close file handle."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# ==================== UTILITY FUNCTIONS ====================

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes (int): Size in bytes
    
    Returns:
        str: Formatted size string
    """
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(size_bytes)
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.2f} {units[unit_index]}"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent security issues.
    
    Args:
        filename (str): Original filename
    
    Returns:
        str: Sanitized filename
    """
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Ensure filename is not empty
    if not filename or filename == '.':
        filename = 'untitled'
    
    return filename


def ensure_unique_filename(directory: str, filename: str) -> str:
    """
    Ensure filename is unique by adding counter suffix.
    
    Args:
        directory (str): Target directory
        filename (str): Desired filename
    
    Returns:
        str: Unique filename
    """
    base_name, extension = os.path.splitext(filename)
    full_path = os.path.join(directory, filename)
    counter = 1
    
    while os.path.exists(full_path):
        new_filename = f"{base_name}_{counter}{extension}"
        full_path = os.path.join(directory, new_filename)
        counter += 1
    
    return os.path.basename(full_path)


def open_file_location(filepath: str):
    """
    Open file location in system file explorer.
    
    Args:
        filepath (str): Path to file
    """
    import platform
    import subprocess
    
    try:
        abs_path = os.path.abspath(filepath)
        
        if platform.system() == 'Windows':
            subprocess.run(['explorer', '/select,', abs_path])
        elif platform.system() == 'Darwin':  # macOS
            subprocess.run(['open', '-R', abs_path])
        else:  # Linux
            subprocess.run(['xdg-open', os.path.dirname(abs_path)])
    
    except Exception as e:
        print(f"Could not open file location: {e}")


# ==================== TESTING ====================

def test_file_handler():
    """Test enhanced file handling."""
    print("=" * 50)
    print("Enhanced File Handler Test")
    print("=" * 50)
    
    # Create test file
    test_dir = "test_files"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    test_file = os.path.join(test_dir, "test.txt")
    test_content = b"Hello, World!" * 1000
    
    with open(test_file, 'wb') as f:
        f.write(test_content)
    
    print(f"\n✓ Created test file: {test_file}")
    print(f"  Size: {format_file_size(len(test_content))}")
    
    # Test file info
    info = get_file_info(test_file)
    print(f"\nFile Info:")
    print(f"  Name: {info['filename']}")
    print(f"  Size: {format_file_size(info['filesize'])}")
    print(f"  Hash: {info['hash'][:16]}...")
    print(f"  Chunks: {info['total_chunks']}")
    print(f"  Large file: {info['is_large']}")
    
    # Test progress tracking
    print(f"\nTesting progress tracking...")
    
    def progress_callback(current, total):
        percent = (current / total) * 100
        print(f"  Progress: {percent:.1f}% ({format_file_size(current)}/{format_file_size(total)})")
    
    with FileReader(test_file, progress_callback=progress_callback) as reader:
        output_file = "test_output.txt"
        with FileWriter(output_file, reader.total_size, progress_callback=progress_callback) as writer:
            chunk_num = 0
            while True:
                chunk = reader.read_chunk()
                if not chunk:
                    break
                
                writer.write_chunk(chunk)
                chunk_num += 1
            
            print(f"\n✓ Transfer complete")
            print(f"  Total chunks: {chunk_num}")
            print(f"  Output: {writer.get_filepath()}")
    
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
    if os.path.exists(output_file):
        os.remove(os.path.join(DOWNLOADS_FOLDER, output_file))
    if os.path.exists(test_dir):
        os.rmdir(test_dir)
    
    print("\n" + "=" * 50)
    print("✓ All tests completed")
    print("=" * 50)


if __name__ == "__main__":
    test_file_handler()