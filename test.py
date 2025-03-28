# 3.3.1 Handle The Packet Metadata First
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

# 3.3.2 Handle the packet payload
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