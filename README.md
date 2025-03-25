# simple_tcp
Implements a simplified for TCP with custom header packet headers, and flow/congestion control.

- Project 3 for CSDS 325: Networks
- @bluey22
- Python: 3.10.12 Linux: 22.0.4 Ubuntu

Please see [TCP Notes](tcp_notes.md) for further information about TCP.

# Complete TCP State Machine
<img src="./images/tcp_state_diagram.png" alt="TCP State Diagram" width="400"/>

# Order of progress
- Added TCPState enum to track (https://book.systemsapproach.org/e2e/tcp.html#adaptive-retransmission)
- Updated packet header format (seq, ack, ctrl_flags, adv_window, SACK Block)
- Implemented Connection Management (SYN, FIN, and ACKS)
- Add reliable data transfer with sliding window
- Add RTT estimation
- Implement SACK and fast retransmit
