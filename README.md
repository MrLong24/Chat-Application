# Socket-based Chat Application with Advanced File Transfer

## 1. Introduction
This project is a real-time chat application developed using TCP socket programming in Python.  
The system follows a client–server architecture and is inspired by modern chat platforms.

The application focuses on:
- Real-time communication
- Multi-client support
- Robust message handling
- Advanced file transfer with pause/resume capability

This project is implemented as part of a group assignment for the Computer Networking / Socket Programming course.

---

## 2. Key Features

### Tier 1 – Core Chat Features
- Real-time text messaging
- Multi-client chat support
- User status management:
  - Online
  - Busy
- Typing indicator (“User is typing…”)
- Message delivery states:
  - Sent
  - Delivered
  - Read
- Message timestamp and grouping
- Automatic reconnection handling when network is unstable

### Tier 2 – Advanced File Transfer
- Multiple concurrent file transfers
- Independent transfer progress tracking
- Pause / Resume / Cancel file transfer
- Receiver-controlled file acceptance or rejection
- Non-blocking chat during file transmission
- Chunk-based file transfer over TCP
- Clear transfer states:
  - Pending
  - In progress
  - Completed
  - Cancelled
  - Rejected

---

## 3. System Architecture

The application follows a **Client–Server architecture**:

- **Server**
  - Manages client connections
  - Handles authentication
  - Routes chat messages
  - Coordinates file transfer sessions

- **Client**
  - Provides graphical user interface (Tkinter)
  - Sends and receives chat messages
  - Manages file transfers independently
  - Displays real-time status updates

The system uses **multi-threading** to ensure that chat and file transfer operations do not block each other.

---

## 4. Communication Protocol

The application uses a custom JSON-based protocol over TCP sockets.

### Main message types:
- `LOGIN`
- `LOGOUT`
- `CHAT_MESSAGE`
- `USER_STATUS`
- `TYPING_START`
- `TYPING_STOP`
- `MESSAGE_DELIVERED`
- `MESSAGE_READ`

### File transfer protocol:
- `FILE_OFFER`
- `FILE_ACCEPT`
- `FILE_REJECT`
- `FILE_CHUNK`
- `FILE_PAUSE`
- `FILE_RESUME`
- `FILE_CANCEL`
- `FILE_COMPLETE`

Each message contains:
- Message type
- Sender
- Receiver
- Payload data

---

## 5. Technologies Used
- Python
- TCP Socket Programming
- Multithreading
- Tkinter (GUI)
- JSON (data serialization)

---

## 6. How to Run the Application

### Step 1: Start the Server
```bash
python server/server.py
```
### Step 2: Start Client
```bash
python client/client.py