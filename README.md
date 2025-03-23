# simple_tcp
Implements a simplified for TCP with custom header packet headers, and flow/congestion control.

- Project 3 for CSDS 325: Networks
- @bluey22
- Python: 3.10.12 Linux: 22.0.4 Ubuntu

# TCP State Machine
![image](https://github.com/user-attachments/assets/a73449e5-67c5-464c-a53c-a798610a5cdd)

# Order of progress
- Added TCPState enum to track (https://book.systemsapproach.org/e2e/tcp.html#adaptive-retransmission)
- Updated packet header format (seq, ack, ctrl_flags, adv_window, SACK Block)

