#!/usr/bin/env python3

# simple_tcp_test.py
import os
import time
import random
import string
import logging
import subprocess
import threading
import matplotlib.pyplot as plt
from transport import TransportSocket, ReadMode

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Create results directory
os.makedirs("results", exist_ok=True)

class SimpleMetrics:
    """Simple class to collect metrics during the test"""
    def __init__(self):
        self.times = []
        self.cwnd = []
        self.rtt = []
        self.throughput = []
        self.bytes_sent = 0
        self.start_time = None
    
    def record(self, time_val, cwnd_val, rtt_val):
        self.times.append(time_val)
        self.cwnd.append(cwnd_val)
        self.rtt.append(rtt_val)
        
        # Calculate throughput
        if self.start_time is not None:
            elapsed = max(0.001, time_val - self.start_time)
            self.throughput.append(self.bytes_sent / elapsed)
        else:
            self.throughput.append(0)

class MonitoredSocket(TransportSocket):
    """Extended TransportSocket that records metrics"""
    def __init__(self, metrics):
        super().__init__()
        self.metrics = metrics
        self.stop_monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start a thread to periodically record metrics"""
        self.stop_monitoring = False
        self.metrics.start_time = time.time()
        self.monitor_thread = threading.Thread(target=self._monitor_metrics)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.stop_monitoring = True
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def _monitor_metrics(self):
        """Periodically record metrics"""
        while not self.stop_monitoring and not self.dying:
            with self.recv_lock:
                current_time = time.time()
                
                # Get current values
                cwnd_val = self.congestion_control["cwnd"] if hasattr(self, "congestion_control") else 0
                rtt_val = self.rtt_estimation["estimated_rtt"] if hasattr(self, "rtt_estimation") else 0
                
                # Record metrics
                self.metrics.record(current_time, cwnd_val, rtt_val)
            
            # Sleep for a short interval
            time.sleep(0.1)
    
    def send(self, data):
        """Override send to track bytes sent"""
        result = super().send(data)
        self.metrics.bytes_sent += len(data)
        return result

def generate_random_data(size):
    """Generate random data of specified size"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def configure_network(loss_percent=0):
    """Configure network conditions using tc"""
    try:
        # Clear any existing settings
        subprocess.run(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"], check=False)
        
        # Add packet loss if specified
        if loss_percent > 0:
            subprocess.run(["sudo", "tc", "qdisc", "add", "dev", "lo", "root", "netem", "loss", f"{loss_percent}%"], check=True)
            logging.info(f"Network configured with {loss_percent}% packet loss")
    except subprocess.SubprocessError as e:
        logging.error(f"Failed to configure network: {e}")

def reset_network():
    """Reset network conditions"""
    try:
        subprocess.run(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"], check=False)
        logging.info("Network conditions reset")
    except subprocess.SubprocessError as e:
        logging.error(f"Failed to reset network: {e}")

def plot_metrics(metrics, test_name):
    """Generate three simple plots: cwnd, RTT, and throughput"""
    # Convert times to relative time from start
    if metrics.times:
        start_time = metrics.times[0]
        rel_times = [t - start_time for t in metrics.times]
        
        # Plot congestion window
        plt.figure(figsize=(8, 4))
        plt.plot(rel_times, metrics.cwnd)
        plt.title(f'Congestion Window - {test_name}')
        plt.xlabel('Time (s)')
        plt.ylabel('Bytes')
        plt.grid(True)
        plt.savefig(f"results/cwnd_{test_name}.png")
        
        # Plot RTT
        plt.figure(figsize=(8, 4))
        plt.plot(rel_times, metrics.rtt)
        plt.title(f'Round Trip Time - {test_name}')
        plt.xlabel('Time (s)')
        plt.ylabel('Seconds')
        plt.grid(True)
        plt.savefig(f"results/rtt_{test_name}.png")
        
        # Plot throughput
        plt.figure(figsize=(8, 4))
        plt.plot(rel_times, metrics.throughput)
        plt.title(f'Throughput - {test_name}')
        plt.xlabel('Time (s)')
        plt.ylabel('Bytes/s')
        plt.grid(True)
        plt.savefig(f"results/throughput_{test_name}.png")
        
        logging.info(f"Plots for {test_name} saved to results directory")

def run_server(server_ready_event, server_done_event, metrics):
    """Run server that receives data"""
    server_socket = MonitoredSocket(metrics)
    server_socket.socket(sock_type="TCP_LISTENER", port=54321)
    
    # Start monitoring metrics
    server_socket.start_monitoring()
    
    # Signal that server is ready
    server_ready_event.set()
    
    # Receive data
    buf = [b""]
    total_received = 0
    
    while True:
        received = server_socket.recv(buf, 64*1024, flags=ReadMode.NO_FLAG)
        if received == 0:  # Connection closed
            break
        total_received += received
    
    logging.info(f"Server received {total_received} bytes total")
    
    # Send a small response back
    server_socket.send(b"ACK")
    
    # Close the socket
    server_socket.close()
    
    # Signal that server is done
    server_done_event.set()

def run_client(server_ready_event, data_size=512*1024):
    """Run client that sends data"""
    # Wait for server to be ready
    server_ready_event.wait()
    
    # Create client socket
    client_socket = TransportSocket()
    client_socket.socket(sock_type="TCP_INITIATOR", port=54321, server_ip="127.0.0.1")
    
    # Generate and send data
    data = generate_random_data(data_size)
    logging.info(f"Client sending {len(data)} bytes")
    
    start_time = time.time()
    client_socket.send(data)
    elapsed = time.time() - start_time
    
    logging.info(f"Data sent in {elapsed:.2f} seconds ({len(data)/elapsed:.2f} bytes/s)")
    
    # Receive response
    buf = [b""]
    client_socket.recv(buf, 1024, flags=ReadMode.NO_FLAG)
    
    # Close the connection
    client_socket.close()

def run_test(test_name, packet_loss=0, data_size=512*1024):
    """Run a complete test with server and client"""
    logging.info(f"Starting test: {test_name}")
    
    # Configure network conditions
    configure_network(packet_loss)
    
    # Create metrics collector
    metrics = SimpleMetrics()
    
    # Create events for synchronization
    server_ready = threading.Event()
    server_done = threading.Event()
    
    # Start server in separate thread
    server_thread = threading.Thread(
        target=run_server,
        args=(server_ready, server_done, metrics)
    )
    server_thread.start()
    
    # Run client
    run_client(server_ready, data_size)
    
    # Wait for server to finish
    server_done.wait(timeout=10)
    
    # Reset network conditions
    reset_network()
    
    # Generate plots
    plot_metrics(metrics, test_name)
    
    # Print some statistics
    if metrics.cwnd:
        avg_cwnd = sum(metrics.cwnd) / len(metrics.cwnd)
        max_cwnd = max(metrics.cwnd)
        logging.info(f"Average cwnd: {avg_cwnd:.2f} bytes, Max cwnd: {max_cwnd:.2f} bytes")
    
    if metrics.rtt:
        avg_rtt = sum(metrics.rtt) / len(metrics.rtt)
        logging.info(f"Average RTT: {avg_rtt:.6f} seconds")
    
    if metrics.throughput:
        avg_throughput = sum(metrics.throughput) / len(metrics.throughput)
        logging.info(f"Average throughput: {avg_throughput:.2f} bytes/s")
    
    return metrics

def main():
    """Run tests with different network conditions"""
    # Test with normal conditions
    normal_metrics = run_test("normal", packet_loss=0, data_size=512*1024)
    
    # Small delay to let everything settle
    time.sleep(1)
    
    # Test with 10% packet loss
    loss_metrics = run_test("loss_10pct", packet_loss=10, data_size=512*1024)
    
    logging.info("Tests completed successfully")

if __name__ == "__main__":
    main()