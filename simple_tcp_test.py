import matplotlib.pyplot as plt
import numpy as np
import time
import socket
import threading
import random
import logging
import os
import sys
from transport import TransportSocket, ReadMode, TCPState  # Import from your file

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('matplotlib.font_manager').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Constants
TEST_DATA_SIZE = 500  # Size of data to transfer
SEND_CHUNK_SIZE = 100  # Size of chunks to send at once
TEST_DURATION = 2      # Total test duration in seconds (Hopefully)
PORT = 12345

# Class to collect and store metrics
class MetricsCollector:
    def __init__(self):
        self.rtt_values = []
        self.throughput_values = []
        self.cwnd_values = []
        self.time_values = []
        self.start_time = None
        self.total_bytes_sent = 0
    
    def reset(self):
        self.rtt_values = []
        self.throughput_values = []
        self.cwnd_values = []
        self.time_values = []
        self.start_time = None
        self.total_bytes_sent = 0
    
    def start(self):
        self.start_time = time.time()
    
    def record(self, socket, bytes_sent, current_time=None):
        if current_time is None:
            current_time = time.time()
            
        if self.start_time is None:
            self.start_time = current_time
            
        elapsed = current_time - self.start_time
        
        # Get RTT from the socket
        rtt = socket.rtt_estimation["estimated_rtt"]
        
        # Calculate throughput (bytes per second)
        self.total_bytes_sent = bytes_sent
        throughput = bytes_sent / max(0.1, elapsed)  # Avoid division by zero
        
        # Get cwnd from socket
        cwnd = socket.congestion_control["cwnd"]
        
        self.time_values.append(elapsed)
        self.rtt_values.append(rtt)
        self.throughput_values.append(throughput)
        self.cwnd_values.append(cwnd)
        
        # Log the values for debugging
        if len(self.time_values) % 10 == 0:  # Log every 10th sample to reduce noise
            logger.info(f"Time: {elapsed:.2f}s, RTT: {rtt:.4f}s, Throughput: {throughput/1000:.2f} KB/s, CWND: {cwnd}")

# Server function
def server_function(metrics_collector):
    server = TransportSocket()
    result = server.socket("TCP_LISTENER", PORT)
    if result != 0:
        logger.error("Failed to create server socket")
        return
        
    logger.info(f"Server started on port {PORT}")
    
    # Wait for data
    buf = [None]  # Wrapper to store received data
    total_received = 0
    
    while True:
        received = server.recv(buf, 4096, ReadMode.NO_WAIT)
        if received > 0:
            total_received += received
            logger.debug(f"Received {received} bytes, total: {total_received}")
        
        # Record metrics
        current_time = time.time()
        if metrics_collector.start_time and (current_time - metrics_collector.start_time) < TEST_DURATION:
            metrics_collector.record(server, total_received, current_time)
        
        # Check if we need to end the test
        if metrics_collector.start_time and (current_time - metrics_collector.start_time) >= TEST_DURATION:
            logger.info(f"Test duration reached, closing server after {current_time - metrics_collector.start_time:.2f}s")
            break
            
        # Small delay to avoid busy waiting
        time.sleep(0.2)
    
    # Close connection
    server.close()
    logger.info(f"Server received {total_received} bytes in total")

# Client function
def client_function(metrics_collector, condition_name):
    client = TransportSocket()
    result = client.socket("TCP_INITIATOR", PORT, "127.0.0.1")
    if result != 0:
        logger.error("Failed to create client socket")
        return
        
    logger.info(f"Client connected to server, starting {condition_name} test")
    
    # Create test data
    data = bytes([random.randint(0, 255) for _ in range(TEST_DATA_SIZE)])
    
    # Start metrics collection
    metrics_collector.start()
    logger.info(f"Starting {condition_name} test")
    
    # Send data in chunks to simulate continuous traffic
    total_sent = 0
    start_time = time.time()
    
    while time.time() - start_time < TEST_DURATION:
        # Send a chunk of data
        chunk_size = min(SEND_CHUNK_SIZE, TEST_DATA_SIZE - total_sent)
        if chunk_size <= 0:
            # Wrap around if we've sent all the data
            total_sent = 0
            continue
            
        chunk = data[total_sent:total_sent + chunk_size]
        client.send(chunk)
        total_sent += chunk_size
        
        # Record metrics
        current_time = time.time()
        metrics_collector.record(client, total_sent, current_time)
        
        # Small delay to avoid overwhelming the server
        time.sleep(0.05)
    
    # Close connection
    client.close()
    logger.info(f"Client sent {total_sent} bytes in total")
    return total_sent

# Run a test with the given network conditions
def run_test(condition_name):
    logger.info(f"Starting {condition_name} test")
    metrics = MetricsCollector()
    
    # Start server thread
    server_thread = threading.Thread(target=server_function, args=(metrics,))
    server_thread.daemon = True
    server_thread.start()
    
    # Give server time to start
    time.sleep(1)
    
    # Start client
    total_sent = client_function(metrics, condition_name)
    
    # Wait for server to finish
    server_thread.join(timeout=5)
    
    logger.info(f"{condition_name} test completed. Total bytes sent: {total_sent}")
    return metrics

# Main function
def main():
    # First test: Normal conditions
    logger.info("Running test with normal network conditions")
    normal_metrics = run_test("Normal Conditions")
    
    # Set up network emulation for lossy test
    logger.info("\nPlease run this command in a separate terminal:")
    logger.info("sudo tc qdisc add dev lo root netem delay 100ms loss 5%")
    input("Press Enter after running the command to continue with the lossy test...")
    
    # Second test: Lossy conditions
    logger.info("Running test with 5% packet loss and 100ms delay")
    lossy_metrics = run_test("Lossy Conditions")
    
    # Clean up network emulation
    logger.info("\nPlease run this command in a separate terminal to restore normal network conditions:")
    logger.info("sudo tc qdisc del dev lo root netem")
    input("Press Enter after running the command to continue...")
    
    # Plot the results
    plot_metrics(normal_metrics, lossy_metrics)

def plot_metrics(normal_metrics, lossy_metrics):
    """Create and save plots comparing the two test conditions"""
    plt.figure(figsize=(12, 12))
    
    # Plot RTT
    plt.subplot(3, 1, 1)
    plt.plot(normal_metrics.time_values, normal_metrics.rtt_values, 'b-', linewidth=2, label='Normal')
    plt.plot(lossy_metrics.time_values, lossy_metrics.rtt_values, 'r-', linewidth=2, label='5% Loss, 100ms Delay')
    plt.title('Round Trip Time (RTT)', fontsize=14)
    plt.xlabel('Time (s)', fontsize=12)
    plt.ylabel('RTT (s)', fontsize=12)
    plt.grid(True)
    plt.legend(fontsize=12)
    
    # Plot Throughput
    plt.subplot(3, 1, 2)
    plt.plot(normal_metrics.time_values, [t/1000 for t in normal_metrics.throughput_values], 'b-', linewidth=2, label='Normal')
    plt.plot(lossy_metrics.time_values, [t/1000 for t in lossy_metrics.throughput_values], 'r-', linewidth=2, label='5% Loss, 100ms Delay')
    plt.title('Throughput', fontsize=14)
    plt.xlabel('Time (s)', fontsize=12)
    plt.ylabel('Throughput (KB/s)', fontsize=12)
    plt.grid(True)
    plt.legend(fontsize=12)
    
    # Plot CWND
    plt.subplot(3, 1, 3)
    plt.plot(normal_metrics.time_values, normal_metrics.cwnd_values, 'b-', linewidth=2, markersize=5, label='Normal')
    plt.plot(lossy_metrics.time_values, lossy_metrics.cwnd_values, 'r-', linewidth=2, label='5% Loss, 100ms Delay')
    plt.title('Congestion Window (cwnd)', fontsize=14)
    plt.xlabel('Time (s)', fontsize=12)
    plt.ylabel('CWND (bytes)', fontsize=12)
    plt.grid(True)
    plt.legend(fontsize=12)
    
    plt.tight_layout()
    plt.savefig('tcp_performance_comparison.png')
    print(f"Saved performance comparison plot to tcp_performance_comparison.png")
    
    # Show some statistics
    print("\nPerformance Statistics:")
    print("Normal Conditions:")
    print(f"  - Average RTT: {np.mean(normal_metrics.rtt_values):.4f} seconds")
    print(f"  - Average Throughput: {np.mean([t/1000 for t in normal_metrics.throughput_values]):.2f} KB/s")
    print(f"  - Average CWND: {np.mean(normal_metrics.cwnd_values):.2f} bytes")
    print(f"  - Total data transferred: {normal_metrics.total_bytes_sent} bytes")
    
    print("\nLossy Conditions (10% loss, 100ms delay):")
    print(f"  - Average RTT: {np.mean(lossy_metrics.rtt_values):.4f} seconds")
    print(f"  - Average Throughput: {np.mean([t/1000 for t in lossy_metrics.throughput_values]):.2f} KB/s")
    print(f"  - Average CWND: {np.mean(lossy_metrics.cwnd_values):.2f} bytes")
    print(f"  - Total data transferred: {lossy_metrics.total_bytes_sent} bytes")
    
    # Calculate performance impact
    rtt_increase = (np.mean(lossy_metrics.rtt_values) / np.mean(normal_metrics.rtt_values) - 1) * 100
    throughput_decrease = (1 - np.mean(lossy_metrics.throughput_values) / np.mean(normal_metrics.throughput_values)) * 100
    cwnd_decrease = (1 - np.mean(lossy_metrics.cwnd_values) / np.mean(normal_metrics.cwnd_values)) * 100
    
    print("\nPerformance Impact:")
    print(f"  - RTT increased by: {rtt_increase:.2f}%")
    print(f"  - Throughput decreased by: {throughput_decrease:.2f}%")
    print(f"  - Congestion window decreased by: {cwnd_decrease:.2f}%")

if __name__ == "__main__":
    main()