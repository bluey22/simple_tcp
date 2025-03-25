# transport.py
import logging
import socket
import struct
import threading
import time
import random
from enum import Enum
from grading import *

# Settings - From grading.py or explicit here
_MSS = MSS                                                # Maximum Segment Size
_DEFAULT_TIMEOUT = DEFAULT_TIMEOUT                        # Default retransmission timeout (seconds)
_MAX_NETWORK_BUFFER = MAX_NETWORK_BUFFER                  # Maximum network buffer size (64KB)
_MSL = 4.0  # Maximum segment lifetime (2.0s for testing, recommended: 120s)
_WINDOW_INITIAL_WINDOW_SIZE = WINDOW_INITIAL_WINDOW_SIZE  # Initial window size (in MSS) - PART 2
_WINDOW_INITIAL_SSTHRESH = WINDOW_INITIAL_SSTHRESH        # Initial slow start threshold - PART 2
_ALPHA = 0.125

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants for simplified TCP
SYN_FLAG = 0x8   # Synchronization flag 
ACK_FLAG = 0x4   # Acknowledgment flag
FIN_FLAG = 0x2   # Finish flag 
SACK_FLAG = 0x1  # Selective Acknowledgment flag 

# Constants for API response codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1

# TCP Connection State:
class TCPState(Enum):
    # Initial States
    CLOSED = 0          # Initial state when no connection exists
    LISTEN = 1          # Server is waiting for connection requests

    # Connection establishment
    SYN_SENT = 2        # Client has sent SYN, now waiting for SYN+ACK
    SYN_RECEIVED = 3    # Server received SYN, sent SYN+ACK. waiting for ACK
    ESTABLISHED = 4     # Connection established, data can be exchanged (SYN, SYNACK, ACK)

    # Connection termination - initiator/client path
    FIN_WAIT_1 = 5      # Initiator sent FIN, waiting for ACK
    FIN_WAIT_2 = 6      # Initiator received ACK for FIN, sent ACK, app needs to close
    TIME_WAIT = 7        # Waiting to ensure remote TCP received the ACK of its FIN

    # Connection termination - receiver/server path
    CLOSE_WAIT = 8      # Receiver received FIN, sent ACK, app needs to close
    LAST_ACK = 9        # Receiver sent FIN, waiting for final ACK

    # Special case - both sides initiating close
    CLOSING = 10         # Both sides sent FIN at the same time, waiting for ACK

    # Client (Active Open):
    #   - CLOSED → SYN_SENT: Client sends SYN
    #   - SYN_SENT → ESTABLISHED: Client receives SYN+ACK, sends ACK
    #   - ESTABLISHED → FIN_WAIT_1: Client sends FIN
    #   - FIN_WAIT_1 → FIN_WAIT_2: Client receives ACK for FIN
    #   - FIN_WAIT_2 → TIME_WAIT: Client receives FIN, sends ACK
    #   - TIME_WAIT → CLOSED: After 2*MSL timeout
    # 
    # Server (Passive Open):
    #   - CLOSED → LISTEN: Server listens for connections
    #   - LISTEN → SYN_RECEIVED: Server receives SYN, sends SYN+ACK
    #   - SYN_RECEIVED → ESTABLISHED: Server receives ACK
    #   - ESTABLISHED → CLOSE_WAIT: Server receives FIN, sends ACK
    #   - CLOSE_WAIT → LAST_ACK: Server sends FIN
    #   - LAST_ACK → CLOSED: Server receives ACK for FIN

class ReadMode:
    NO_FLAG = 0  # Blocking read
    NO_WAIT = 1  # Non-blocking read
    TIMEOUT = 2  # Timeout-based read

class Packet:
    def __init__(
            self, 
            seq=0, 
            ack=0, 
            flags=0, 
            adv_window=_MAX_NETWORK_BUFFER,
            sack_left=0,
            sack_right=0,
            payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags            # Control Flags (SYN, ACK, FIN)
        self.adv_window = adv_window  # Advertised window size
        self.sack_left = sack_left    # Left edge of SACK block
        self.sack_right = sack_right  # Right edge of SACK block
        self.payload = payload
        #   (SACK) Selective Acknowledgment allows the receiver to inform the sender about
        #     non-contiguous blocks of data that have been received successfully
        #
        #   - sack_left is the starting sequence number of a successfully received data block (inclusive)
        #   - sack_right is the ending sequence number (exclusive) of that block
        #   - A SACK block is a range of numbers
        #
        #   e.g.,
        #   - We can ACK 2000, but SACK (3000, 4000), meaning we want (2000, 3000) - Missing Block
        #   - Sender can resend missing block only

    def encode(self):
        # Encode the packet header and payload into bytes
        # Format (in bytes):
        #       - seq(4)
        #       - ack(4)
        #       - flags(1)
        #       - advertised_window(2)
        #       - sack_left(4)
        #       - sack_right(4)
        #       - payload_len(2)
        # 
        # Binary String Packing:
        # ! - Network byte order (big endian)
        # I - Unsigned int (4 bytes) 
        # B - Unsigned char (1 byte)
        # H - Unsigned short (2 bytes)
        header = struct.pack("!IIBHIIH", 
                            self.seq, 
                            self.ack, 
                            self.flags, 
                            self.adv_window,
                            self.sack_left,
                            self.sack_right,
                            len(self.payload))
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIBHIIH")
        seq, ack, flags, adv_window, sack_left, sack_right, payload_len = struct.unpack("!IIBHIIH", data[:header_size])
        payload = data[header_size:header_size+payload_len]
        return Packet(seq, ack, flags, adv_window, sack_left, sack_right, payload)


class TransportSocket:
    def __init__(self):
        # Frontend Conn Socket
        self.sock_fd = None

        # Locks (Synchronize backend thread and app/API thread)
        self.recv_lock = threading.Lock()
        #   - Protects access to receive buffer and window dictionary data (only 1 app thread, atomicity)
        #   - Sync state, updates, prevent corruption, etc.

        self.send_lock = threading.Lock()
        #   - Protects access to send operations and window dictionary data (only 1 app thread, atomicity)

        # Blocking Read Usage: App level thread calls recv() OR wait_for_ack()
        self.wait_cond = threading.Condition(self.recv_lock)
        #   -> self.wait_cond.wait() : due to blocking call to recv() 
        #           - but no data in buffer
        #           - wait() releases self.recv_lock
        #           - puts app level thread to sleep
        #           - ... after awoken, can perform the read
        #   -> self.wait_cond.notify_all() : due to backend receiving valid data packet
        #           - acquires self.recv_lock
        #           - updates buffer and recv_len, releases lock
        #           - acquires lock with wait_cond to wake up threads, releases the lock
        #           - notify_all() : defense programming to wake up all threads,
        #                            though concurrent recv() calls to TransportSocket may be a 
        #                            design issue

        self.death_lock = threading.Lock()  # Signals thread termination
        #   - Useful when dealing with a shutdown state, not just an atomic boolean, 
        #       need to send last data and clean up socket (FIN)
        #   - Useful if App thread performs concurrent actions that updates the self.dying obj, maybe a timeout thread
        #   - Helps protect against multiple close() calls (not likely), and creates memory visibility (likely) to
        #       synchronize backend read of self.dying by app modifications to it
        #   - Protects against torn reads, compiler optimizations, etc.

        # Socket State
        self.dying = False
        self.thread = None  # For backend() thread
        self.state = TCPState.CLOSED
        self.state_lock = threading.Lock()  # Safe read/writes to self.state

        # Connection Info
        self.sock_type = None
        self.conn = None  # Set by client during socket() creation or by server when first packet is received
        self.my_port = None

        # Flow Control and Reliability
        self.window = {
            "last_ack": 0,                      # The next seq we expect from peer (used for receiving data)
            "next_seq_expected": 0,             # The highest ack we've received for *our* transmitted data
            "recv_buf": b"",                    # Received data buffer
            "recv_len": 0,                      # How many bytes are in recv_buf
            "next_seq_to_send": 0,              # The sequence number for the next packet we send
            "adv_window": _MAX_NETWORK_BUFFER,  # Advertised window from peer

            "send_buffer": {},      # Buffer for sent but unacknowledged data
            #   - { key: seq#, val: (data_chunk/payload, send_time) }
            #   - For retransmission, RTT estimation, Flow Control, Fast Retransmit and SACK

            "unordered_data": {},   # Buffer for received out-of-order data
            #   - { key: seq#, val: data_chunk }
        }

        # RTT estimation
        self.rtt_estimation = {
            "estimated_rtt": 1.0,     # Initial estimated RTT (seconds)
            "alpha": _ALPHA,          # EWMA weight factor (recommended in RFC)
            "last_sample": None,      # Last RTT sample
            "timestamp": {},          # Timestamp when a segment was sent
            #   - { key: seq#, val: time.time() }
        }
        
        # SACK and duplicate ACK detection
        self.dup_acks = 0
        self.last_ack_received = 0
        self.sack_blocks = []
            
    # ---------------------------- Public API Methods ------------------------------------
    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            self._set_state(TCPState.CLOSED)
            self.conn = (server_ip, port)
            self.sock_fd.bind(("", 0))  # Bind to any available local port
        elif sock_type == "TCP_LISTENER":
            self._set_state(TCPState.LISTEN)
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
        else:
            print("Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can periodically check `self.dying`
        # TODO: Verify
        self.sock_fd.settimeout(1.0)

        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self._backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS
    
    def connect(self):
        """
        Establish a connection with the server (TCP three-way handshake)
        """
        # 1. Validate TCPState can connect()
        if self.sock_type != "TCP_INITIATOR":
            logger.error("connect() can only be called on TCP_INITIATOR sockets")
            return EXIT_ERROR
        
        if self._get_state() != TCPState.CLOSED:
            logger.error("Socket is not in CLOSED state ()")
            return EXIT_ERROR
        
        # 2. Initiator formulates request packet
        initial_seq = random.randint(0, 65535)  # Initiator selects a random initial sequence number
        self.window["next_seq_to_send"] = initial_seq  # Single threaded connect mode, no need for lock
        syn_packet = Packet(seq=initial_seq, flags=SYN_FLAG, adv_window=MAX_NETWORK_BUFFER)

        # 3. Send SYN packet and mark send time for RTT estimation
        self.sock_fd.sendto(syn_packet.encode(), self.conn)
        self.rtt_estimation["timestamp"][initial_seq] = time.time()

        # 4. Update state
        self._set_state(TCPState.SYN_SENT)
        logger.info(f"Sent SYN packet with initial seq={initial_seq}")

        # 5. Wait for SYN-ACK (with timeout, blocking)
        timeout = time.time() + DEFAULT_TIMEOUT * 3  # Longer timeout for initial connection
        connected = False

        while time.time() < timeout and not connected:
            # Sleep and check if state changed to ESTABLISHED 
            #   (backend thread handles setting from SYN-ACK)
            time.sleep(0.1)
            if self._get_state() == TCPState.ESTABLISHED:
                connected = True

        # Check timeout
        if not connected:
            logger.error("Connection timed out waiting for SYN-ACK")
            self._set_state(TCPState.CLOSED)  # Close connection, valid state to try again
            return EXIT_ERROR
        
        logger.info("Connection established")
        return EXIT_SUCCESS

    def accept(self):
        """
        Accept an incoming connection (for listener sockets).
        """
        # 1. Validate TCPState can accept()
        if self.sock_type != "TCP_LISTENER":
            logger.error("accept() can only be called on TCP_LISTENER sockets")
            return EXIT_ERROR
            
        if self._get_state() != TCPState.LISTEN:
            logger.error("Socket is not in LISTEN state")
            return EXIT_ERROR
        
        # 2. Wait for a connection to be established
        timeout = time.time() + 30  # 30-second timeout for accept
        accepted = False

        while time.time() < timeout and not accepted:
            # Wait for state to change to ESTABLISHED
            # (backend thread will set and send SYN-ACK)
            time.sleep(1.0)
            if self._get_state() == TCPState.ESTABLISHED:
                accepted = True
        
        if not accepted:
            logger.error("Accept timed out waiting for connection")
            return EXIT_ERROR
    
        logger.info("Connection accepted")
        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket and stop the backend thread.
        """

        # 1. Evaluate current state to apply close()
        current_state = self._get_state()

        # 2. Handle pending sends and receives
        self._ensure_all_data_sent()
        #   - Reads handled by app level (Don't call close if still want to read)

        # 3. Handle connection termination based on current state
        if current_state in [TCPState.ESTABLISHED, TCPState.SYN_RECEIVED]:
            # Active close - send FIN
            self._initiate_active_close()
        elif current_state == TCPState.CLOSE_WAIT:
            # Passive close - respond to received FIN with our own FIN
            self._complete_passive_close()
        elif current_state in [TCPState.SYN_SENT, TCPState.LISTEN]:
            # No connection to terminate, just close
            self._set_state(TCPState.CLOSED)
        
        # 4. Signal the backend thread to terminate
        self.death_lock.acquire()
        try:
            self.dying = True
        finally:
            self.death_lock.release()

        if self.thread:
            self.thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        else:
            print("Error: Null socket")
            return EXIT_ERROR

        return EXIT_SUCCESS

    def send(self, data):
        """
        Send data reliably to the peer (stop-and-wait style).
        """
        if not self.conn:
            raise ValueError("Connection not established.")
        
        # We can all send data in a ESTABLISHED connection state
        if self._get_state() != TCPState.ESTABLISHED:
            raise ValueError("Connection not in ESTABLISHED state.")
        
        # Handles concurrent send() calls from app level threads
        #   - does NOT block the backend thread
        with self.send_lock:
            self.send_segment(data)
        
        return len(data)

    def recv(self, buf, length, flags):
        """
        Retrieve received data from the buffer, with optional blocking behavior.

        :param buf: Buffer to store received data (list of bytes or bytearray).
        :param length: Maximum length of data to read
        :param flags: ReadMode flag to control blocking behavior
        :return: Number of bytes read
        """
        read_len = 0

        if length < 0:
            print("ERROR: Negative length")
            return EXIT_ERROR

        # If blocking read, wait until there's data in buffer
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0:
                    self.wait_cond.wait()

        self.recv_lock.acquire()
        try:
            if flags in [ReadMode.NO_WAIT, ReadMode.NO_FLAG]:
                if self.window["recv_len"] > 0:
                    read_len = min(self.window["recv_len"], length)
                    buf[0] = self.window["recv_buf"][:read_len]

                    # Remove data from the buffer
                    if read_len < self.window["recv_len"]:
                        self.window["recv_buf"] = self.window["recv_buf"][read_len:]
                        self.window["recv_len"] -= read_len
                    else:
                        self.window["recv_buf"] = b""
                        self.window["recv_len"] = 0
            else:
                print("ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        finally:
            self.recv_lock.release()

        return read_len

    # --------------------------- Private/Internal Methods ----------------------------
    def _set_state(self, new_state):
        """Set the TCP state with proper locking."""
        with self.state_lock:
            logger.info(f"Transitioning from {self.state} to {new_state}")
            self.state = new_state
    
    def _get_state(self):
        """Get the current TCP state with proper locking."""
        with self.state_lock:
            return self.state
        
    def _ensure_all_data_sent(self):
        """
        Calculated wait that monitors the send_buffer (sent but unacknowledged data)
        """
        # 1. Acquire send_lock to check the send_buffer
        with self.send_lock:
            if self.window["send_buffer"]:
                logger.info("Waiting for all data to be acknowledged before closing")
                
                # 2. Wait loop for acknowledgements
                deadline = time.time() + 10
                while self.window["send_buffer"] and time.time() < deadline:
                    self.send_lock.release()
                    time.sleep(0.2)
                    self.send_lock.acquire()
                
                # 3. Exit
                if self.window["send_buffer"]:
                    logger.warning("Closing with unsent data - connection may be lost")

    def _initiate_active_close(self):
        # 1. Create FIN Packet and send
        fin_packet = Packet(
            seq=self.window["next_seq_to_send"], 
            ack=self.window["last_ack"], 
            flags=FIN_FLAG,
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        self.window["next_seq_to_send"] += 1  # FIN consumes 1 sequence number
        self._set_state(TCPState.FIN_WAIT_1)
        logger.info(f"Sent FIN packet with seq={fin_packet.seq}")
        
        # 2. Wait for FINACK or CLOSED (10 seconds)
        timeout = time.time() + 10
        while time.time() < timeout and self._get_state() not in [TCPState.TIME_WAIT, TCPState.CLOSED]:
            time.sleep(0.2)
            
        # 3. Allow any delayed packets in the network to expire before fully closing the socket
        #       - Prevents old duplicate packets from being misinterpreted
        if self._get_state() == TCPState.TIME_WAIT:
            logger.info("Entering TIME_WAIT state for 2*MSL")
            time.sleep(2*_MSL)
            self._set_state(TCPState.CLOSED)
    
    def _complete_passive_close(self):
        # 1. Create FIN Packet and send
        fin_packet = Packet(
            seq=self.window["next_seq_to_send"], 
            ack=self.window["last_ack"], 
            flags=FIN_FLAG,
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        self.window["next_seq_to_send"] += 1  # FIN consumes 1 sequence number
        self._set_state(TCPState.LAST_ACK)
        logger.info(f"Sent FIN packet with seq={fin_packet.seq}")
        
        # 2. Wait for FINACK (transition to CLOSED)
        timeout = time.time() + 5
        while time.time() < timeout and self._get_state() != TCPState.CLOSED:
            time.sleep(0.1)

    def send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments and reliably wait for each ACK
        
        Runs under send lock, can safely access self.window's send contexts
        """
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
            payload_len = min(_MSS, total_len - offset)

            # Current sequence number
            seq_no = self.window["next_seq_to_send"]
            chunk = data[offset : offset + payload_len]

            # Create a packet
            segment = Packet(seq=seq_no, ack=self.window["last_ack"], flags=0, payload=chunk)

            # We expect an ACK for seq_no + payload_len
            ack_goal = seq_no + payload_len

            while True:
                print(f"Sending segment (seq={seq_no}, len={payload_len})")
                self.sock_fd.sendto(segment.encode(), self.conn)

                if self.wait_for_ack(ack_goal):
                    print(f"Segment {seq_no} acknowledged.")
                    # Advance our next_seq_to_send
                    self.window["next_seq_to_send"] += payload_len
                    break
                else:
                    print("Timeout: Retransmitting segment.")

            offset += payload_len


    def wait_for_ack(self, ack_goal):
        """
        Wait for 'next_seq_expected' to reach or exceed 'ack_goal' within _DEFAULT_TIMEOUT.
        Return True if ack arrived in time; False on timeout.
        """
        with self.recv_lock:
            start = time.time()
            while self.window["next_seq_expected"] < ack_goal:
                elapsed = time.time() - start
                remaining = _DEFAULT_TIMEOUT - elapsed
                if remaining <= 0:
                    return False

                self.wait_cond.wait(timeout=remaining)

            return True

    def _backend(self):
        """
        Backend loop to handle receiving data and sending acknowledgments.
        All incoming packets are read in this thread only, to avoid concurrency conflicts.
        """
        while not self.dying:
            try:
                data, addr = self.sock_fd.recvfrom(2048)
                packet = Packet.decode(data)

                # If no peer is set, establish connection (for listener)
                if self.conn is None:
                    self.conn = addr

                # If it's an ACK packet, update our sending side
                if (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                        self.wait_cond.notify_all()
                    continue

                # Otherwise, assume it is a data packet
                # Check if the sequence matches our 'last_ack' (in-order data)
                if packet.seq == self.window["last_ack"]:
                    with self.recv_lock:
                        # Append payload to our receive buffer
                        self.window["recv_buf"] += packet.payload
                        self.window["recv_len"] += len(packet.payload)

                    with self.wait_cond:
                        self.wait_cond.notify_all()

                    print(f"Received segment {packet.seq} with {len(packet.payload)} bytes.")

                    # Send back an acknowledgment
                    ack_val = packet.seq + len(packet.payload)
                    ack_packet = Packet(seq=0, ack=ack_val, flags=ACK_FLAG)
                    self.sock_fd.sendto(ack_packet.encode(), addr)
                    # Update last_ack
                    self.window["last_ack"] = ack_val
                else:
                    # For a real TCP, we need to send duplicate ACK or ignore out-of-order data
                    print(f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")

            except socket.timeout:
                continue
        
            except Exception as e:
                if not self.dying:
                    print(f"Error in backend: {e}")

