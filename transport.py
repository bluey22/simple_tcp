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
_MSS = MSS                                # Maximum Segment Size
_DEFAULT_TIMEOUT = DEFAULT_TIMEOUT        # Default retransmission timeout (seconds)
_MAX_NETWORK_BUFFER = MAX_NETWORK_BUFFER  # Maximum network buffer size (64KB)
_MSL = 20.0     # Maximum segment lifetime (20.0s for testing, recommended: 120s)
_ALPHA = 0.125  # For RTT Estimation (Smoothing Factor)

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

class ReadMode:
    NO_FLAG = 0  # Blocking read
    NO_WAIT = 1  # Non-blocking read
    TIMEOUT = 2  # Timeout-based read


class TCPState(Enum):
    # Initial States
    CLOSED = 0          # Initial state when no connection exists
    LISTEN = 1          # Server is waiting for connection requests

    # Connection establishment
    SYN_SENT = 2        # Client has sent SYN, now waiting for SYN+ACK
    SYN_RCVD = 3        # Server received SYN, sent SYN+ACK. waiting for ACK
    ESTABLISHED = 4     # Connection established, data can be exchanged (SYN, SYNACK, ACK)

    # Connection termination - initiator/client path
    FIN_WAIT_1 = 5      # Initiator sent FIN, waiting for ACK
    FIN_WAIT_2 = 6      # Initiator received ACK for FIN, sent ACK, app needs to close
    TIME_WAIT = 7       # Waiting to ensure remote TCP received the ACK of its FIN

    # Connection termination - receiver/server path
    CLOSE_WAIT = 8      # Receiver received FIN, sent ACK, app needs to close
    LAST_ACK = 9        # Receiver sent FIN, waiting for final ACK


class Packet:
    def __init__(self, seq=0, ack=0, flags=0, adv_window=MAX_NETWORK_BUFFER, payload=b""):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.adv_window = adv_window
        self.payload = payload

    def encode(self):
        # Encode the packet header and payload into bytes
        # Format: seq (32 bits), ack (32 bits), flags (32 bits), adv_window (16 bits)
        header = struct.pack("!IIIH", self.seq, self.ack, self.flags, self.adv_window)
        return header + self.payload

    @staticmethod
    def decode(data):
        # Decode bytes into a Packet object
        header_size = struct.calcsize("!IIIH")
        seq, ack, flags, adv_window = struct.unpack("!IIIH", data[:header_size])
        payload = data[header_size:]
        return Packet(seq, ack, flags, adv_window, payload)


class TransportSocket:
    def __init__(self):
        # Connection Start
        self.sock_fd = None
        self.sock_type = None
        self.conn = None
        self.my_port = None
        self.state = TCPState.CLOSED

        # Locks
        self.recv_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.wait_cond = threading.Condition(self.recv_lock)

        self.death_lock = threading.Lock()
        self.dying = False
        self.thread = None

        # SLiding Window Algorithm Management
        self.window = {
            # Receiving
            "last_ack": 0,    # The next seq we expect from peer (used for receiving data)
            "recv_buf": b"",  # Received data buffer
            "recv_len": 0,    # How many bytes are in recv_buf
            
            # Sending
            "next_seq_expected": 0,   # The highest ack we've received for *our* transmitted data
            "next_seq_to_send": 0,    # Next sequence number to send to peer
            "send_base": 0,           # Base of sending window (oldest unacked byte)
            "packets_in_flight": {},  # Unacked but Sent {seq: (packet, send_time)}
            "send_buffer": b"",

            # Monitoring
            "in_flight": 0,           # Bytes in flight (sent but not acked)
            "peer_adv_window": _MAX_NETWORK_BUFFER,  # Peer's advertised window
        }

        # RTT estimation
        self.rtt_estimation = {
            "estimated_rtt": 1.0,     # Initial estimated RTT (seconds)
            "alpha": _ALPHA,          # EWMA weight factor (recommended in RFC)
            "last_sample": None,      # Last RTT sample
            "timestamps": {},          # Timestamp when a segment was sent
            #   - { key: seq#, val: time.time() }
        }

    # ---------------------------- Public API Methods ------------------------------------
    def socket(self, sock_type, port, server_ip=None):
        """
        Create and initialize the socket, setting its type and starting the backend thread.
        """
        self.sock_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_type = sock_type

        if sock_type == "TCP_INITIATOR":
            self.state = TCPState.CLOSED
            self.conn = (server_ip, port)  # active open (passive open sets conn in backend())
            self.sock_fd.bind(("", 0))  # Bind to any available local port
        elif sock_type == "TCP_LISTENER":
            self.state = TCPState.LISTEN
            self.sock_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_fd.bind(("", port))
        else:
            print("Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can periodically check `self.dying`
        self.sock_fd.settimeout(1.0)

        # Set our own port
        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self._backend, daemon=True)
        self.thread.start()
        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket and stop the backend thread.
        """
        self._ensure_all_data_sent()

        # Handle connection termination based on the current state
        if self.state == TCPState.ESTABLISHED:
            self._initiate_close()
        elif self.state == TCPState.CLOSE_WAIT:
            self._handle_close_wait()
        
        # Tell the backend threat to stop
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
            print(str(time.time()), "Error: Null socket")
            return EXIT_ERROR

        return EXIT_SUCCESS

    def send(self, data):
        """
        Send data reliably to the peer (stop-and-wait style).
        """
        # Still in passive open, can't send
        if not self.conn:
            raise ValueError("Connection not established.")
        
        # In active open, needs to connect first:
        if self.state == TCPState.CLOSED and self.sock_type == "TCP_INITIATOR":
            self._connect()
        
        # We can all send data in a ESTABLISHED connection state
        if self.state != TCPState.ESTABLISHED:
            raise ValueError("Connection not in ESTABLISHED state.")
        
        with self.send_lock:
            self._send_segment(data)

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
            print(str(time.time()), "ERROR: Negative length")
            return EXIT_ERROR

        # If blocking read, wait until there's data in buffer
        if flags == ReadMode.NO_FLAG:
            with self.wait_cond:
                while self.window["recv_len"] == 0:
                    # If we're in CLOSE_WAIT and buffer is empty, return 0 (EOF)
                    if self.state == TCPState.CLOSE_WAIT:
                        return 0
                    self.wait_cond.wait()

        # Perform read
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
                    
                    # Send window update if we've freed a >quarter of our window with our read
                    available_space = _MAX_NETWORK_BUFFER - self.window["recv_len"]
                    if (available_space > _MAX_NETWORK_BUFFER / 4):
                        
                        if self.conn:
                            window_update = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=available_space
                            )
                            logger.debug(f"Sending window update with adv_window={available_space}")
                            self.sock_fd.sendto(window_update.encode(), self.conn)
            else:
                print(str(time.time()), "ERROR: Unknown or unimplemented flag.")
                read_len = EXIT_ERROR
        finally:
            self.recv_lock.release()

        return read_len

    # ---------------------------- Private close() helpers ------------------------------------
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

    def _initiate_close(self):
        print("Initiating connection termination...")
        # 1. Create FIN Packet and send
        fin_packet = Packet(
            seq=self.window["next_seq_to_send"], 
            ack=self.window["last_ack"], 
            flags=FIN_FLAG,
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        self.state = TCPState.FIN_WAIT_1
        logger.info(f"Sent FIN packet with seq={fin_packet.seq}")
        
        # 2. Wait for ACK or FIN+ACK
        timeout = time.time() + _DEFAULT_TIMEOUT * 4
        with self.wait_cond:
            while self.state != TCPState.TIME_WAIT and self.state != TCPState.CLOSED:
                if time.time() >= timeout:
                    # Timeout, retransmit FIN
                    print(str(time.time()), "FIN timeout, retransmitting...")
                    self.sock_fd.sendto(fin_packet.encode(), self.conn)
                    timeout = time.time() + _DEFAULT_TIMEOUT * 4          

                self.wait_cond.wait(timeout=1.0)
                
                # Check if we're dying
                if self.dying:
                    break
        
        # If in TIME_WAIT, wait for 2*MSL before fully closing
        if self.state == TCPState.TIME_WAIT:
            print(str(time.time()), "In TIME_WAIT, waiting for 2*MSL...")
            time.sleep(2 * _DEFAULT_TIMEOUT)
            self.state = TCPState.CLOSED
            
        print(str(time.time()), "Connection terminated")

    def _handle_close_wait(self):
        """Handle passive close after entering CLOSE_WAIT state."""
        logger.info("In CLOSE_WAIT state, sending FIN")
        
        # Send our own FIN
        fin_packet = Packet(
            seq=self.window["next_seq_to_send"], 
            ack=self.window["last_ack"], 
            flags=FIN_FLAG,
            adv_window=_MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        
        # Update state
        self.state = TCPState.LAST_ACK
        logger.info(f"Sent FIN, moved to LAST_ACK")
        
        # Wait for ACK
        timeout = time.time() + _DEFAULT_TIMEOUT * 3
        
        with self.wait_cond:
            while self.state != TCPState.CLOSED:
                if time.time() >= timeout:
                    # Timeout, retransmit FIN
                    logger.warning("FIN timeout, retransmitting...")
                    self.sock_fd.sendto(fin_packet.encode(), self.conn)
                    timeout = time.time() + _DEFAULT_TIMEOUT * 3
                
                # Wait for state change or timeout
                self.wait_cond.wait(timeout=1.0)
                
                # Check if we're dying
                self.death_lock.acquire()
                try:
                    if self.dying:
                        return
                finally:
                    self.death_lock.release()
        
        logger.info("Connection closed (passive side)")

    # ---------------------------- Private send() helpers ------------------------------------
    def _connect(self):
        """
        create connection for the first send()
        """
        # 1. Initiator formulates SYN/request packet
        initial_seq = random.randint(0, 65535)
        self.window["next_seq_to_send"] = initial_seq
        
        syn_packet = Packet(
            seq=initial_seq, 
            ack=0, 
            flags=SYN_FLAG, 
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        
        # 2. Send SYN packet and mark send time for RTT estimation
        self.sock_fd.sendto(syn_packet.encode(), self.conn)
        self.rtt_estimation["timestamps"][initial_seq] = time.time()
        self.state = TCPState.SYN_SENT
        logger.info(f"Sent SYN packet with initial seq={initial_seq}")
        
        # 3. Wait for SYN-ACK
        timeout = time.time() + _DEFAULT_TIMEOUT * 3  # Longer timeout for initial connection

        with self.wait_cond:
            while self.state != TCPState.ESTABLISHED:
                if time.time() >= timeout:
                    # Timeout, retransmit SYN and reset timeout
                    print("SYN timeout, retransmitting...")
                    self.sock_fd.sendto(syn_packet.encode(), self.conn)
                    timeout = time.time() + _DEFAULT_TIMEOUT * 3
                
                # Wait for state change or timeout
                self.wait_cond.wait(timeout=1.0)
                
                # Check if we're dying
                if self.dying:
                    raise ValueError("Socket is closing")
        
        print(f"{time.time()} Connection established successfully")

    def _send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments with flow control
        """
        offset = 0
        total_len = len(data)

        # While there's data left to send
        while offset < total_len:
            with self.wait_cond:
                # Wait for window space to be available
                while self.window["in_flight"] >= self.window["peer_adv_window"]:
                    print(f"Flow control: waiting for window space (in_flight={self.window['in_flight']}, peer_window={self.window['peer_adv_window']})")
                    self.wait_cond.wait(timeout=0.3)
                    if self.dying:
                        return
                
                # Calculate how much we can send now
                available_window = self.window["peer_adv_window"] - self.window["in_flight"]
                payload_len = min(_MSS, total_len - offset, available_window)
                
                if payload_len <= 0:
                    continue
                    
                # Get sequence number for this segment
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset:offset + payload_len]
                
                # Create and send packet
                segment = Packet(
                    seq=seq_no, 
                    ack=self.window["last_ack"], 
                    flags=0, 
                    adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"],
                    payload=chunk
                )
                
                print(f"Sending segment (seq={seq_no}, len={payload_len}, window={available_window})")
                self.sock_fd.sendto(segment.encode(), self.conn)
                
                # Update window tracking
                self.window["next_seq_to_send"] += payload_len
                self.window["in_flight"] += payload_len
                self.rtt_estimation["timestamps"][seq_no] = time.time()
                self.window["packets_in_flight"][seq_no] = (segment, time.time())
                
                # Check for ACKs on all sent packets
                # TODO, potentially allow multiple calls to send() without blocks (use send buffer and offset)
                start_wait = time.time()
                while seq_no in self.window["packets_in_flight"]:
                    # Check for timeout and retransmit if needed
                    current_time = time.time()
                    if current_time - self.window["packets_in_flight"][seq_no][1] > _DEFAULT_TIMEOUT:
                        print(f"Timeout: Retransmitting segment (seq={seq_no})")
                        self.sock_fd.sendto(segment.encode(), self.conn)
                        self.window["packets_in_flight"][seq_no] = (segment, current_time)
                    
                    # Wait for a short time to check for ACKs
                    self.wait_cond.wait(timeout=0.1)
                    
                    # Give up after reasonable timeout to avoid deadlock
                    if current_time - start_wait > 10:  # 10 seconds total timeout
                        print("Giving up on waiting for ACK after 10 seconds")
                        break
                
                # Move to next segment
                offset += payload_len

    # ---------------------------- Connection Control Helpers ------------------------------------
    def _time_wait_to_closed(self):
        """Helper method to transition from TIME_WAIT to CLOSED after 2*MSL."""
        try:
            # Wait for 2*MSL
            time.sleep(2 * _MSL)
            
            # Check if we're still in TIME_WAIT
            with self.wait_cond:
                if self.state == TCPState.TIME_WAIT:
                    self.state = TCPState.CLOSED
                    self.wait_cond.notify_all()
                    logger.info("TIME_WAIT expired, moved to CLOSED")
        except Exception as e:
            logger.error(f"Error in TIME_WAIT transition: {e}")

    # ---------------------------- Flow Control Helpers ------------------------------------

    def _update_rtt_estimate(self, sample_rtt):
        """Update RTT estimation using EWMA algorithm."""
        # EstimatedRTT = alpha × EstimatedRTT + (1 - alpha) × SampleRTT
        self.rtt_estimation["estimated_rtt"] = (
            self.rtt_estimation["alpha"] * self.rtt_estimation["estimated_rtt"] +
            (1 - self.rtt_estimation["alpha"]) * sample_rtt
        )
        
        # Update last sample
        self.rtt_estimation["last_sample"] = sample_rtt
        
        logger.debug(f"Updated RTT estimate: {self.rtt_estimation['estimated_rtt']:.3f}s (sample: {sample_rtt:.3f}s)")
        return self.rtt_estimation["estimated_rtt"]
    
    # ---------------------------- Private backend() helpers ------------------------------------
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
                    
                # Update peer advertised window for flow control
                self.window["peer_adv_window"] = packet.adv_window

                # Connection establishment handling
                if self.state == TCPState.LISTEN and (packet.flags & SYN_FLAG) != 0:
                    # Received SYN in LISTEN state
                    with self.recv_lock:
                        print(f"{time.time()} Received SYN from {addr}")
                        
                        # SYN consumes one sequence number, so next expected byte is packet.seq + 1
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Initialize our own sequence number for this connection
                        initial_seq = 0  # For simplicity; could be random
                        
                        # Send SYN+ACK
                        syn_ack = Packet(
                            seq=initial_seq, 
                            ack=self.window["last_ack"], 
                            flags=SYN_FLAG | ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(syn_ack.encode(), addr)
                        
                        # Update our sequence numbers
                        # After sending SYN, our next sequence number is initial_seq + 1
                        self.window["next_seq_to_send"] = initial_seq + 1
                        self.window["send_base"] = initial_seq + 1
                        self.window["send_next"] = initial_seq + 1
                        
                        # Transition to SYN_RCVD
                        self.state = TCPState.SYN_RCVD
                        self.wait_cond.notify_all()
                    continue

                elif self.state == TCPState.SYN_SENT and (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                    # Received SYN+ACK in SYN_SENT state
                    with self.recv_lock:
                        print(f"{time.time()} Received SYN+ACK from {addr}")
                        
                        # SYN consumes one sequence number, so next expected byte is packet.seq + 1
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Our own SYN consumes one sequence number as well
                        # The acknowledgment (packet.ack) should be our initial seq + 1
                        initial_seq = self.window["next_seq_to_send"]
                        if packet.ack == initial_seq + 1:
                            # Update RTT estimation
                            if initial_seq in self.rtt_estimation["timestamps"]:
                                self._update_rtt_estimate(initial_seq)
                            
                            # Send ACK (final handshake step)
                            ack_packet = Packet(
                                seq=packet.ack,  # This is our next sequence number (initial_seq + 1)
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                            
                            # Update sequence numbers for data transmission
                            # After the SYN, our sequence numbers start at initial_seq + 1
                            self.window["next_seq_to_send"] = packet.ack
                            self.window["next_seq_expected"] = packet.ack
                            self.window["send_base"] = packet.ack
                            self.window["send_next"] = packet.ack
                            
                            # Transition to ESTABLISHED
                            self.state = TCPState.ESTABLISHED
                            self.wait_cond.notify_all()
                        else:
                            print(f"Invalid ACK: expected {initial_seq + 1}, got {packet.ack}")
                    continue

                elif self.state == TCPState.SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in SYN_RCVD state (completing three-way handshake)
                    with self.recv_lock:
                        print(f"{time.time()} Received ACK from {addr}, handshake complete")
                        
                        # The client is acknowledging our SYN
                        expected_ack = self.window["send_base"]
                        if packet.ack == expected_ack:
                            # Transition to ESTABLISHED
                            self.state = TCPState.ESTABLISHED
                            self.wait_cond.notify_all()
                            
                            print(f"Window update: base={self.window['send_base']}, next={self.window['send_next']}, " +
                                f"in_flight={len(self.window['packets_in_flight']) if 'packets_in_flight' in self.window else 0}, adv_window={packet.adv_window}")
                        else:
                            print(f"Invalid ACK: expected {expected_ack}, got {packet.ack}")
                    continue

                # Connection termination handling
                elif self.state == TCPState.ESTABLISHED and (packet.flags & FIN_FLAG) != 0:
                    # Received FIN in ESTABLISHED state (passive close)
                    with self.recv_lock:
                        print(str(time.time()), f"Received FIN from {addr}")
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Send ACK
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        # Transition to CLOSE_WAIT
                        self.state = TCPState.CLOSE_WAIT
                        self.wait_cond.notify_all()
                        
                        # Immediately send FIN and transition to LAST_ACK
                        # This is a simplification where we don't wait for application to close
                        fin_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=FIN_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(fin_packet.encode(), addr)
                        self.state = TCPState.LAST_ACK
                    continue

                elif self.state == TCPState.FIN_WAIT_1 and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in FIN_SENT state
                    with self.recv_lock:
                        print(str(time.time()), f"Received ACK for FIN from {addr}")
                        
                        # Only transition if this is an ACK for our FIN
                        if packet.ack > self.window["next_seq_expected"]:
                            self.window["next_seq_expected"] = packet.ack
                            self.state = TCPState.TIME_WAIT
                            self.wait_cond.notify_all()
                            
                            # Schedule transition to CLOSED after 2*MSL
                            threading.Timer(2 * _DEFAULT_TIMEOUT, self._time_wait_to_closed).start()
                    continue

                elif self.state == TCPState.FIN_WAIT_2 and (packet.flags & FIN_FLAG) != 0:
                    # Received FIN in FIN_SENT state (simultaneous close)
                    with self.recv_lock:
                        print(str(time.time()), f"Received FIN from {addr} (simultaneous close)")
                        self.window["last_ack"] = packet.seq + 1
                        
                        # Send ACK
                        ack_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
                        self.sock_fd.sendto(ack_packet.encode(), addr)
                        
                        # Transition to TIME_WAIT
                        self.state = TCPState.TIME_WAIT
                        self.wait_cond.notify_all()
                        
                        # Schedule transition to CLOSED after 2*MSL
                        threading.Timer(2 * _DEFAULT_TIMEOUT, self._time_wait_to_closed()).start()
                    continue

                elif self.state == TCPState.LAST_ACK and (packet.flags & ACK_FLAG) != 0:
                    # Received ACK in LAST_ACK state (completing passive close)
                    with self.recv_lock:
                        print(str(time.time()), f"Received final ACK from {addr}")
                        self.state = TCPState.CLOSED
                        self.wait_cond.notify_all()
                    continue

                # Data packet handling (ACK packets with or without data)
                if (packet.flags & ACK_FLAG) != 0:
                    with self.recv_lock:
                        # Check if this ACK advances our window
                        if packet.ack > self.window["next_seq_expected"]:
                            # Calculate how many bytes were acknowledged
                            acked_bytes = packet.ack - self.window["next_seq_expected"]
                            self.window["next_seq_expected"] = packet.ack
                            
                            # Update peer's advertised window
                            self.window["peer_adv_window"] = packet.adv_window
                            
                            # Update in-flight data count
                            self.window["in_flight"] = max(0, self.window["in_flight"] - acked_bytes)
                            
                            # Remove acknowledged packets from in-flight list
                            for seq in list(self.window["packets_in_flight"].keys()):
                                pkt, _ = self.window["packets_in_flight"][seq]
                                if seq + len(pkt.payload) <= packet.ack:
                                    # Update RTT estimation
                                    if seq in self.rtt_estimation["timestamps"]:
                                        self._update_rtt_estimate(seq)
                                    # Remove from in-flight list
                                    del self.window["packets_in_flight"][seq]
                            
                            print(f"Window update: base={self.window['next_seq_expected']}, " +
                                f"in_flight={self.window['in_flight']}, adv_window={packet.adv_window}")
                            
                            # Notify any waiting sender
                            self.wait_cond.notify_all()

                # Data packet processing (if in ESTABLISHED state)
                if self.state in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT] and len(packet.payload) > 0:
                    with self.recv_lock:
                        # Check if this packet is within our receive window
                        if packet.seq == self.window["last_ack"]:
                            # Check if we have space in the receive buffer
                            available_space = _MAX_NETWORK_BUFFER - self.window["recv_len"]
                            
                            if available_space >= len(packet.payload):
                                # Append payload to our receive buffer
                                self.window["recv_buf"] += packet.payload
                                self.window["recv_len"] += len(packet.payload)
                                
                                print(f"Received data segment {packet.seq} with {len(packet.payload)} bytes.")
                                
                                # Update last_ack
                                self.window["last_ack"] = packet.seq + len(packet.payload)
                                
                                # Calculate new advertised window
                                adv_window = _MAX_NETWORK_BUFFER - self.window["recv_len"]
                                
                                # Send ACK with current window advertisement
                                ack_packet = Packet(
                                    seq=self.window["next_seq_to_send"], 
                                    ack=self.window["last_ack"], 
                                    flags=ACK_FLAG, 
                                    adv_window=adv_window
                                )
                                self.sock_fd.sendto(ack_packet.encode(), addr)
                                
                                self.wait_cond.notify_all()
                            else:
                                # Buffer full, send ACK with reduced window
                                print(f"Receive buffer limited: {available_space} bytes available")
                                ack_packet = Packet(
                                    seq=self.window["next_seq_to_send"], 
                                    ack=self.window["last_ack"], 
                                    flags=ACK_FLAG, 
                                    adv_window=available_space
                                )
                                self.sock_fd.sendto(ack_packet.encode(), addr)
                        elif packet.seq > self.window["last_ack"]:
                            # Out-of-order packet, send duplicate ACK
                            print(f"Out-of-order packet: received seq={packet.seq}, expected={self.window['last_ack']}")
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                        else:
                            # Duplicate packet, send ACK
                            print(f"Duplicate packet: received seq={packet.seq}, already received up to={self.window['last_ack']}")
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                elif len(packet.payload) > 0:
                    # Out-of-order or duplicate packet
                    print(str(time.time()), f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")
                    
                    # Send duplicate ACK
                    ack_packet = Packet(
                        seq=self.window["next_seq_to_send"], 
                        ack=self.window["last_ack"], 
                        flags=ACK_FLAG, 
                        adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                    )
                    self.sock_fd.sendto(ack_packet.encode(), addr)

            except socket.timeout:
                continue
            
            except Exception as e:
                if not self.dying:
                    print(str(time.time()), f"Error in backend: {e}")