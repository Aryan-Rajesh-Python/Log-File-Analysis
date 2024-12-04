import re
import csv
import logging
import threading
import argparse
import os
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

# Set up logging (Rotating log handler to avoid large log files)
def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Rotating log file, max size 1MB, 3 backups
    handler = RotatingFileHandler('sample.log', maxBytes=10**6, backupCount=3)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Parse command-line arguments for configuration
def parse_arguments():
    parser = argparse.ArgumentParser(description="Log File Analysis")
    parser.add_argument('--login-threshold', type=int, default=3, help="Threshold for failed login attempts")
    parser.add_argument('--chunk-size', type=int, default=1000, help="Size of each log chunk for processing")
    return parser.parse_args()

# Define enhanced IP extraction regex (supports IPv4 and IPv6)
ip_regex = re.compile(r'(\d{1,3}\.){3}\d{1,3}|\[([A-Fa-f0-9:]+)\]')

# IP Validation
def is_valid_ip(ip):
    try:
        # Validate IPv4 format (simple check enough)
        if re.match(r'(\d{1,3}\.){3}\d{1,3}', ip):  # IPv4 validation
            return all(0 <= int(part) <= 255 for part in ip.split('.'))
        
        # Validate IPv6 format (full validation)
        if re.match(r'\[([A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\]', ip):  # Full IPv6 address
            return True
        elif re.match(r'\[([A-Fa-f0-9]{1,4}:){1,7}:\]', ip):  # IPv6 address with "::" (compressed)
            return True
        return False
    except Exception as e:
        logging.error(f"Error validating IP address {ip}: {e}")
        return False

# Initialize thread lock for thread-safety
lock = threading.Lock()

# Function to process a single log file chunk
def process_log_chunk(chunk, ip_requests, endpoint_access, login_attempts):
    local_ip_requests = defaultdict(int)
    local_endpoint_access = defaultdict(int)
    local_login_attempts = defaultdict(int)

    for line in chunk:
        try:
            # Extract IP address (supports both IPv4 and IPv6)
            ip_match = ip_regex.search(line)
            ip_address = ip_match.group(0) if ip_match else None

            if ip_address and is_valid_ip(ip_address):
                local_ip_requests[ip_address] += 1

            # Extract endpoint (e.g., URL or resource path)
            endpoint_match = re.search(r'"(GET|POST|PUT|DELETE) (\S+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(2)
                local_endpoint_access[endpoint] += 1

            # Detect failed login attempts (HTTP status code 401 or "Invalid credentials" message)
            status_code_match = re.search(r'\s(\d{3})\s', line)
            if status_code_match and status_code_match.group(1) == '401':
                if ip_address:
                    local_login_attempts[ip_address] += 1

            # Additional failed login check for "Invalid credentials"
            if 'Invalid credentials' in line and ip_address:
                local_login_attempts[ip_address] += 1
        except Exception as e:
            logging.error(f"Error processing line: {line}\nError: {e}")
            continue  # Skip this line and continue with the next

    # Safely update global dictionaries using a lock
    with lock:
        for ip, count in local_ip_requests.items():
            ip_requests[ip] += count
        for endpoint, count in local_endpoint_access.items():
            endpoint_access[endpoint] += count
        for ip, count in local_login_attempts.items():
            login_attempts[ip] += count

# Function to process the log file in chunks using multithreading for efficiency
def process_log_file(log_file_path, ip_requests, endpoint_access, login_attempts, chunk_size):
    try:
        # Open the log file and split it into chunks
        with open(log_file_path, 'r', encoding='utf-8') as file:
            chunk = []
            num_threads = os.cpu_count()  # Dynamically adjust threads based on the system's CPU cores
            
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = []

                for line in file:
                    chunk.append(line)
                    if len(chunk) == chunk_size:
                        futures.append(executor.submit(process_log_chunk, chunk, ip_requests, endpoint_access, login_attempts))
                        chunk = []  # Reset chunk after submitting
                        
                # Process any remaining lines that didn't fill a full chunk
                if chunk:
                    futures.append(executor.submit(process_log_chunk, chunk, ip_requests, endpoint_access, login_attempts))

                # Wait for all threads to complete
                for future in futures:
                    future.result()

    except (FileNotFoundError, PermissionError, IOError, OSError) as e:
        logging.error(f"Error reading the file '{log_file_path}': {str(e)}")
        return

# Function to display and save results
def display_and_save_results(ip_requests, endpoint_access, login_attempts, login_threshold):
    # 1. Requests per IP Address
    print(f"\n{'='*80}\nRequests per IP Address:\n{'='*80}")
    print(f"{'IP Address':<40} {'Request Count':<15}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<40} {count:<15}")
    
    # 2. Most Frequently Accessed Endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1], default=("None", 0))
    print(f"\n{'='*80}\nMost Frequently Accessed Endpoint:\n{'='*80}")
    print(f"Endpoint: {most_accessed_endpoint[0]}\nAccess Count: {most_accessed_endpoint[1]}")
    
    # 3. Suspicious Activity (Failed login attempts above threshold)
    print(f"\n{'='*80}\nSuspicious Activity Detected:\n{'='*80}")
    print(f"{'IP Address':<40} {'Failed Login Attempts':<25}")
    suspicious_activity_found = False
    for ip, count in login_attempts.items():
        if count >= login_threshold:
            print(f"{ip:<40} {count:<25}")
            suspicious_activity_found = True
    if not suspicious_activity_found:
        print("No suspicious activity detected.")
    
    # Save results to a CSV file with a timestamped name to avoid overwriting
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f'log_analysis_results_{timestamp}.csv'
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP Address
        writer.writerow(['Requests per IP Address:'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line for separation

        # Most Accessed Endpoint
        writer.writerow(['Most Frequently Accessed Endpoint:'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  # Blank line for separation

        # Suspicious Activity
        writer.writerow(['Suspicious Activity Detected:'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        if suspicious_activity_found:
            for ip, count in login_attempts.items():
                if count >= login_threshold:
                    writer.writerow([ip, count])
        else:
            writer.writerow(['No suspicious activity detected', ''])

# Main function to run the analysis
def main():
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    setup_logging()

    # Initialize data structures
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    login_attempts = defaultdict(int)

    # Process the log file
    process_log_file('sample.log', ip_requests, endpoint_access, login_attempts, args.chunk_size)
    
    # Display and save the results
    display_and_save_results(ip_requests, endpoint_access, login_attempts, args.login_threshold)

if __name__ == '__main__':
    main()
