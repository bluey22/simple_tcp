# simple_tcp
Implements TCP over UDP with custom header packet headers, sliding window algorithm, flow controw, and (soon) congestion control.

- Project 3 for CSDS 325: Networks
- @bluey22
- Python: 3.10.12 Linux: 22.0.4 Ubuntu

# HOW TO RUN
Note: Might need to run more than once for coherence - I've tested in multiple conditions and was able to get solid results every time, but just a warning.
1) Open up two terminals
2) run server.py in one, and client.py in the other. You can observe the console outputs directly or use wireshark (see tcp_over_udp.lua)
    - Sometimes you'll see the randomly generated data in the client and/or server, sometimes you won't
        - These are race conditions due to the single recv() call in each, maybe they'll be in the buffer, maybe they won't
        - The application layer / socket program that uses our socket is suppose to parse and account for this, ensuring normal
            usage of the API (always calling close(), responsible calls to send(), recv())
3) At the end of the console, you can see the alpha value and the final estimated RTT (you can play around with the _ALPHA parameter at the top of transport.py)

For 2) you can alter network conditions with the following commands:
```bash
sudo tc qdisc add dev lo root netem delay 200ms loss 20%
sudo tc qdisc del dev lo root netem
```
    - This will allow you to see retransmits and more interesting happenings
    - WIll also change the RTT estimations

Please see [TCP Notes](tcp_notes.md) for further information about TCP that I used to build this.

# Complete TCP State Machine
<img src="./images/tcp_state_diagram.png" alt="TCP State Diagram" width="400"/>


