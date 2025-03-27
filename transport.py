# transport.py
#
# - Ben Luo
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
_MSL = 4.0     # Maximum segment lifetime (4.0s for testing, recommended: 120s)
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
    FIN_SENT = 5        # Sent FIN, waiting for ACK (Combined FIN_WAIT_1 and FIN_WAIT_2)
    #   - see _handle_ack_for_fin_initiator() on this combining of FIN states, 
    #       and extra processing in TIME_WAIT (with added time)
    TIME_WAIT = 6       # Waiting to ensure remote TCP received the ACK of its FIN

    # Connection termination - receiver/server path
    CLOSE_WAIT = 7      # Receiver received FIN, sent ACK, app needs to close
    LAST_ACK = 8        # Receiver sent FIN, waiting for final ACK


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
        self.resend_timeout_thread = None

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
            "unacked_bytes": 0,       # Bytes sent but not acked (in flight or lost )
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
            logging.info("Unknown socket type")
            return EXIT_ERROR

        # 1-second timeout so we can periodically check `self.dying`
        self.sock_fd.settimeout(1.0)

        # Set our own port
        self.my_port = self.sock_fd.getsockname()[1]

        # Start the backend thread
        self.thread = threading.Thread(target=self._backend, daemon=True)
        self.thread.start()

        # Start the send retransmit thread
        self.resend_timeout_thread = threading.Thread(target=self._monitor_timeouts, daemon=True)
        self.resend_timeout_thread.start()

        return EXIT_SUCCESS

    def close(self):
        """
        Close the socket and stop the backend thread.
        """
        logging.info("close() called on TransportSocket")
        self._ensure_all_data_sent()

        # Handle connection termination based on the current state
        if self.state == TCPState.ESTABLISHED:
            logging.debug("Initiated Close")
            self._initiate_close()
        elif self.state == TCPState.CLOSE_WAIT:
            logging.debug("Passive Close (edge case)")
            # True Passive Close is handled in backend, explanation can be found in _handle_close_wait() description
            self._handle_close_wait()
        
        # Tell the backend threat to stop
        self.death_lock.acquire()
        try:
            self.dying = True
        finally:
            self.death_lock.release()

        if self.thread:
            self.thread.join()
        
        if self.resend_timeout_thread:
            self.resend_timeout_thread.join()

        if self.sock_fd:
            self.sock_fd.close()
        else:
            logging.info("Error: Null socket")
            return EXIT_ERROR

        logging.debug(f"Finishing exiting with state = {self.state}")
        logging.info("close() completed successfully")
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
        
        logging.debug(f"API CALL: send(data) called with data = {data}")
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
            logging.error("ERROR: Negative length")
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
                logging.error("ERROR: Unknown or unimplemented flag.")
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
        logging.info("Initiating connection termination...")
        # 1. Create FIN Packet and send
        fin_packet = Packet(
            seq=self.window["next_seq_to_send"], 
            ack=self.window["last_ack"], 
            flags=FIN_FLAG,
            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
        )
        self.sock_fd.sendto(fin_packet.encode(), self.conn)
        self.state = TCPState.FIN_SENT
        logger.info(f"Sent FIN packet with seq={fin_packet.seq}")
        
        # 2. Wait for ACK or FIN+ACK
        timeout = time.time() + _DEFAULT_TIMEOUT * 4
        with self.wait_cond:
            while self.state != TCPState.TIME_WAIT and self.state != TCPState.CLOSED:
                if time.time() >= timeout:
                    # Timeout, retransmit FIN
                    logging.info("FIN timeout, retransmitting...")
                    self.sock_fd.sendto(fin_packet.encode(), self.conn)         

                self.wait_cond.wait(timeout=1.0)

                if time.time() >= timeout + 3:
                    break
                
                # Check if we're dying
                if self.dying:
                    break
        
        # If in TIME_WAIT, wait for 2*MSL before fully closing (SHOULD BLOCK)
        if self.state == TCPState.TIME_WAIT:
            logging.info("Performing Final Message Reception, Cleanup (FIN_WAIT_2 and TIME_WAIT) - waiting for 2*MSL...")
            self._time_wait_to_closed()

        logging.info("Connection terminated")

    def _handle_close_wait(self):
        """
        Handle passive close after entering CLOSE_WAIT state
        - EDGE CASE Handler - we rarely are in CLOSE_WAIT when close() is called, since we send our own fin (close() handles sending last data)
            immediately and move to LAST_ACK
        """
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
        initial_seq = random.randint(0, MAX_NETWORK_BUFFER // 2)
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
        timeout = time.time() + _DEFAULT_TIMEOUT
        logger.info(f"Sent SYN packet with initial seq={initial_seq} (retry in {_DEFAULT_TIMEOUT} seconds)")
        
        # 3. Wait for SYN-ACK
        with self.wait_cond:
            while self.state != TCPState.ESTABLISHED:
                if time.time() >= timeout:
                    # Timeout, retransmit SYN and reset timeout
                    logging.info("SYN timeout, retransmitting...")
                    self.sock_fd.sendto(syn_packet.encode(), self.conn)
                    timeout = time.time() + _DEFAULT_TIMEOUT * 3
                
                # Wait for state change or timeout
                self.wait_cond.wait(timeout=1.0)
                
                # Check if we're dying
                if self.dying:
                    raise ValueError("Socket is closing")
        
        logging.info(f"{time.time()} Connection established successfully")

    def _send_segment(self, data):
        """
        Send 'data' in multiple MSS-sized segments and monitor timeouts for resends
        - Flow Control (Sliding Window w/ Advertised Window and Timeouts)
        """
        # 1. Iterate through data
        offset = 0  # ptr for byte array data
        total_len = len(data)
        while offset < total_len:

            # Safely access window with condition lock ("next_seq_to_send")
            with self.wait_cond:
                
                # 2. Check if there is room to send the data
                while self.window["unacked_bytes"] >= self.window["peer_adv_window"]:
                    logging.info(f"WAIT - send(): Waiting for window space")
                    logging.debug(f"WAIT - send():(unacked_bytes_sent={self.window['unacked_bytes']}, peer_window={self.window['peer_adv_window']})")
                    # Wait for space to open up
                    self.wait_cond.wait(timeout=0.3)

                    # If shutdown, cancel send()
                    if self.dying:
                        return
                
                # 3. Formulate packet with maximum payload_len based on availability
                available_window = self.window["peer_adv_window"] - self.window["unacked_bytes"]
                payload_len = min(_MSS, total_len - offset, available_window)
                
                # Dont send a segment with 0 bytes
                if payload_len <= 0:
                    continue
                    
                seq_no = self.window["next_seq_to_send"]
                chunk = data[offset:offset + payload_len]  # Slice of data that was sent
                
                send_packet = Packet(
                    seq=seq_no, 
                    ack=self.window["last_ack"], 
                    flags=0, 
                    adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"],
                    payload=chunk
                )
                
                logging.info(f"Sending segment (seq={seq_no}, len={payload_len})")
                self.sock_fd.sendto(send_packet.encode(), self.conn)
                
                # 4. Update window tracking
                self.window["next_seq_to_send"] += payload_len
                self.window["unacked_bytes"] += payload_len
                self.rtt_estimation["timestamps"][seq_no] = time.time()
                self.window["packets_in_flight"][seq_no] = (send_packet, time.time())
                
                # Advance data ptr based on what was sent
                offset += payload_len

    def _monitor_timeouts(self):
        """
        Periodically check for packets in flight that have timed out and retransmit them.
        This function should be run in a separate thread.
        """
        while not self.dying:
            with self.wait_cond:
                current_time = time.time()
                for seq_no, (packet, timestamp) in list(self.window["packets_in_flight"].items()):
                    if current_time - timestamp > _DEFAULT_TIMEOUT:
                        logging.info(f"Timeout: Retransmitting segment (seq={seq_no})")
                        self.sock_fd.sendto(packet.encode(), self.conn)
                        # Update the timestamp for the retransmitted packet
                        self.window["packets_in_flight"][seq_no] = (packet, current_time)
                # Notify any waiting threads that window state may have changed (e.g. if ACKs arrive)
                self.wait_cond.notify_all()
            time.sleep(0.5)

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

        # 1. Run until our socket is dying (close() called)
        while not self.dying:

            # 2. Try to read incoming data 
            try:
                # (blocking read, will throw timeout exception after a second then continue)
                data, addr = self.sock_fd.recvfrom(2048)

                # decode our data packet
                packet = Packet.decode(data)

                # (FOR LISTENER) first packet establishes peer connection
                if self.conn is None:
                    self.conn = addr
                    
                # Update peer advertised window for flow control
                self.window["peer_adv_window"] = packet.adv_window

                # 3. Evaluate the type of packet received and handle accordingly

                # debug check
                if packet.flags & FIN_FLAG != 0:
                    logging.debug(f"RECEIVED FIN PACKET, seq={packet.seq}")
                
                # 3.1 CONNECTION ESTABLISHMENT CASES
                if self.state == TCPState.LISTEN and (packet.flags & SYN_FLAG) != 0:
                    # CASE 1: LISTENER RECEIVES SYN, SEND SYN+ACK
                    self._handle_syn(addr, packet)
                    continue

                elif self.state == TCPState.SYN_SENT and (packet.flags & SYN_FLAG) != 0 and (packet.flags & ACK_FLAG) != 0:
                    # CASE 2: INITIATOR RECEIVES SYN+ACK
                    self._handle_syn_ack(addr, packet)
                    continue

                elif self.state == TCPState.SYN_RCVD and (packet.flags & ACK_FLAG) != 0:
                    # CASE 3: LISTENER RECEIVES FINAL ACK OF SYN-ACK
                    self._handle_final_ack_conn(addr, packet)
                    continue

                # 3.2 CONNECTION TERMINATION CASES
                elif self.state == TCPState.ESTABLISHED and (packet.flags & FIN_FLAG) != 0:
                    # CASE 1: RECEIVE FIN REQUEST (LISTENER/PASSIVE CLOSE), ACK and send FIN
                    self._handle_fin_passive(addr, packet)
                    continue

                elif self.state == TCPState.FIN_SENT and (packet.flags & ACK_FLAG) != 0:
                    # CASE 2: ALREADY SENT FIN, RECEIVED ACK (FOR INITIATOR)
                    self._handle_ack_for_fin_initiator(addr, packet)
                    continue

                elif (self.state == TCPState.FIN_SENT or self.state == TCPState.TIME_WAIT) and (packet.flags & FIN_FLAG) != 0:
                    # CASE 3: HANDLING SIMULTANEOUS CLOSE
                    # + EDGE CASE: FIN_WAIT_2 CASE, OUR FIN ACK'ED, BUT WE WANT TO BE SURE TO ACK THEIR FIN WHILE NOT TOTALLY DEAD
                    #   - AKA, Combine FIN_WAIT_2 into TIME_WAIT
                    self._handle_fin_after_fin_sent(addr, packet)
                    continue

                elif self.state == TCPState.LAST_ACK and (packet.flags & ACK_FLAG) != 0:
                    # CASE 4: FINISH PASSIVE CLOSE (RECEIVED ACK IN LAST_ACK STATE)
                    with self.recv_lock:
                        logging.info(f"Received final ACK from {addr}, Transitioning to CLOSED")
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
                            self.window["unacked_bytes"] = max(0, self.window["unacked_bytes"] - acked_bytes)
                            
                            # Remove acknowledged packets from in-flight list
                            for seq in list(self.window["packets_in_flight"].keys()):
                                pkt, _ = self.window["packets_in_flight"][seq]
                                if seq + len(pkt.payload) <= packet.ack:
                                    # Update RTT estimation
                                    if seq in self.rtt_estimation["timestamps"]:
                                        sample_rtt = time.time() - self.rtt_estimation["timestamps"][seq]
                                        self._update_rtt_estimate(sample_rtt)
                                    # Remove from in-flight list
                                    del self.window["packets_in_flight"][seq]
                            
                            logging.info(f"Window update: base={self.window['next_seq_expected']}, " +
                                f"in_flight={self.window['unacked_bytes']}, adv_window={packet.adv_window}")
                            
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
                                
                                logging.info(f"Received data segment {packet.seq} with {len(packet.payload)} bytes.")
                                
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
                                logging.info(f"Receive buffer limited: {available_space} bytes available")
                                ack_packet = Packet(
                                    seq=self.window["next_seq_to_send"], 
                                    ack=self.window["last_ack"], 
                                    flags=ACK_FLAG, 
                                    adv_window=available_space
                                )
                                self.sock_fd.sendto(ack_packet.encode(), addr)
                        elif packet.seq > self.window["last_ack"]:
                            # Out-of-order packet, send duplicate ACK
                            logging.info(f"Out-of-order packet: received seq={packet.seq}, expected={self.window['last_ack']}")
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                        else:
                            # Duplicate packet, send ACK
                            logging.info(f"Duplicate packet: received seq={packet.seq}, already received up to={self.window['last_ack']}")
                            ack_packet = Packet(
                                seq=self.window["next_seq_to_send"], 
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                            self.sock_fd.sendto(ack_packet.encode(), addr)
                elif len(packet.payload) > 0:
                    # Out-of-order or duplicate packet
                    logging.info(f"Out-of-order packet: seq={packet.seq}, expected={self.window['last_ack']}")
                    
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
                    logging.info(f"Error in backend: {e}")

    def _handle_syn(self, addr, packet):
        """
        For Listener: Receives SYN packet from connection, send back SYN+ACK
        """
        with self.recv_lock:
            logging.info(f"{time.time()} Received SYN from {addr}, Sending SYN+ACk")
            
            # 1. Advance window
            self.window["last_ack"] = packet.seq + 1
                        
            # 2. Select starting sequence # and send SYN+ACK
            initial_seq = random.randint(0, MAX_NETWORK_BUFFER // 2)    
            syn_ack = Packet(
                            seq=initial_seq, 
                            ack=self.window["last_ack"], 
                            flags=SYN_FLAG | ACK_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
            self.sock_fd.sendto(syn_ack.encode(), addr)
                        
            # Update our sequence numbers
            self.window["next_seq_to_send"] = initial_seq + 1
            self.window["send_base"] = initial_seq + 1
            self.window["send_next"] = initial_seq + 1
                        
            # Transition to SYN_RCVD
            self.state = TCPState.SYN_RCVD
            self.wait_cond.notify_all()  # Exit our recv_lock and notify

    def _handle_syn_ack(self, addr, packet):
        """
        For Initiator: Receives SYN+ACK packet, ACK and establish connection
        """
        with self.recv_lock:
            logging.info(f"{time.time()} Received SYN+ACK from {addr}, sending ACK")
            
            # Advance window
            self.window["last_ack"] = packet.seq + 1
            initial_seq = self.window["next_seq_to_send"]

            # Check that SYN+ACK has correct ACK
            if packet.ack == initial_seq + 1:

                # Update RTT estimation
                if initial_seq in self.rtt_estimation["timestamps"]:
                    sample_rtt = time.time() - self.rtt_estimation["timestamps"][initial_seq]
                    self._update_rtt_estimate(sample_rtt)
                            
                # Send ACK
                ack_packet = Packet(
                                seq=packet.ack,  # This is our next sequence number (initial_seq + 1)
                                ack=self.window["last_ack"], 
                                flags=ACK_FLAG, 
                                adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                            )
                self.sock_fd.sendto(ack_packet.encode(), addr)
                            
                # Update sequence numbers
                self.window["next_seq_to_send"] = packet.ack
                self.window["next_seq_expected"] = packet.ack
                self.window["send_base"] = packet.ack
                self.window["send_next"] = packet.ack
                            
                # Transition to ESTABLISHED
                self.state = TCPState.ESTABLISHED
                self.wait_cond.notify_all()  # Give up recv_lock and notify
            else:
                logging.info(f"Invalid ACK: expected {initial_seq + 1}, got {packet.ack}")

    def _handle_final_ack_conn(self, addr, packet):
        """
        For Listener: Receives final ACK for SYN+ACK packet, Establish connection
        """
        with self.recv_lock:
            logging.info(f"{time.time()} Received final connection ACK from {addr}, establishing connection")
            expected_ack = self.window["send_base"]

            # Transition to ESTABLISHED
            if packet.ack == expected_ack:
                self.state = TCPState.ESTABLISHED
                self.wait_cond.notify_all()
                            
                logging.info(f"Listener receives final ACK for SYN-ACK, transitioning to {self.state}")
            else:
                logging.info(f"Invalid ACK: expected {expected_ack}, got {packet.ack}")

    def _handle_fin_passive(self, addr, packet):
        """
        For Listener: Receives FIN, ACK and send FIN
        """
        with self.recv_lock:
            logging.info(f"(PASSIVE CLOSE) Received FIN from {addr}, Sending ACK")
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

            # Quick backend check (if close() was called during handle_passive, we already sent our own FIN)
            if self.state == TCPState.FIN_SENT:
                self.state = TCPState.LAST_ACK
                return

            # Send our own FIN
            logging.info(f"Sending FIN request to {addr}")
            fin_packet = Packet(
                            seq=self.window["next_seq_to_send"], 
                            ack=self.window["last_ack"], 
                            flags=FIN_FLAG, 
                            adv_window=MAX_NETWORK_BUFFER - self.window["recv_len"]
                        )
            self.sock_fd.sendto(fin_packet.encode(), addr)
            self.state = TCPState.LAST_ACK

    def _handle_ack_for_fin_initiator(self, addr, packet):
        """
        For Initiator: Receive ACK for FIN, "do nothing"
            - Our version of FIN_WAIT_1 to FIN_WAIT_2
        """
        with self.recv_lock:
            logging.info(f"Received ACK for FIN from {addr} (Already sent FIN)")
                        
            # Only transition if this is an ACK for our FIN
            if packet.ack > self.window["next_seq_expected"]:
                self.window["next_seq_expected"] = packet.ack
                self.state = TCPState.TIME_WAIT
                self.wait_cond.notify_all()
                            
                # Schedule transition to CLOSED after 2*MSL
                threading.Timer(2 * _MSL, self._time_wait_to_closed).start()

    def _handle_fin_after_fin_sent(self, addr, packet):
        """
        For Initiator or Receiver: We deal with a simultaneous FIN and or a FIN reception after a ACK of our FIN
            - We combine FIN_WAIT_2 scenario into our _TIME_WAIT, and increase the wait time by a factor of the
            default timeout to allow for FIN_WAIT_2 handling
        """
        with self.recv_lock:
            logging.info(f"Received FIN from {addr}")
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
            logging.info(f"Sent ACK of FIN to {addr}, transitioning to {TCPState.TIME_WAIT} before closing socket")
            self.state = TCPState.TIME_WAIT
            self.wait_cond.notify_all()
