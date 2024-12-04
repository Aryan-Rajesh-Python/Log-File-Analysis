import re
import csv
import pandas as pd
import logging
from collections import defaultdict
from datetime import datetime

# Set up logging (Only show WARNING and above in terminal)
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the log file path
log_file_path = 'sample.log'

# Initialize data structures to store results
ip_requests = defaultdict(int)
endpoint_access = defaultdict(int)
failed_login_count = defaultdict(int)
invalid_user_count = defaultdict(int)

# Define the threshold for suspicious activity (failed logins)
login_threshold = 3  # Adjust this to the desired threshold (e.g., 3)

# Define a function to process the log file
def process_log_file(log_file_path):
    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                # Extract IP address
                ip_match = re.match(r'(\d{1,3}\.){3}\d{1,3}', line)
                if ip_match:
                    ip_address = ip_match.group(0)
                    ip_requests[ip_address] += 1

                # Extract endpoint (e.g., URL or resource path)
                endpoint_match = re.search(r'"(GET|POST|PUT|DELETE) (\S+)', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(2)
                    endpoint_access[endpoint] += 1

                # Detect failed login attempts (HTTP status code 401)
                status_code_match = re.search(r'\s(\d{3})\s', line)
                if status_code_match and status_code_match.group(1) == '401':
                    failed_login_count[ip_address] += 1

                # Additional failed login check for "Invalid credentials"
                if 'Invalid credentials' in line:
                    invalid_user_count[ip_address] += 1
    except FileNotFoundError:
        logging.error(f"Error: The file '{log_file_path}' was not found.")
        return
    except PermissionError:
        logging.error(f"Error: Permission denied for '{log_file_path}'.")
        return

# Function to display and save results
def display_and_save_results():
    # 1. Requests per IP Address
    logging.debug("\nRequests per IP Address:")  # Change to debug so it won't show in terminal
    print(f"\n{'='*40}\nRequests per IP Address:\n{'='*40}")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<15}")
    
    # 2. Most Frequently Accessed Endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1], default=("None", 0))
    logging.debug(f"Most Frequently Accessed Endpoint: {most_accessed_endpoint[0]} with {most_accessed_endpoint[1]} accesses.")  # Debug
    print(f"\n{'='*40}\nMost Frequently Accessed Endpoint:\n{'='*40}")
    print(f"Endpoint: {most_accessed_endpoint[0]}\nAccess Count: {most_accessed_endpoint[1]}")
    
    # 3. Suspicious Activity (Failed login attempts above threshold)
    logging.debug("Checking for suspicious activity (failed login attempts).")  # Debug
    print(f"\n{'='*40}\nSuspicious Activity Detected:\n{'='*40}")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
    suspicious_activity_found = False
    for ip, count in failed_login_count.items():
        if count >= login_threshold:
            print(f"{ip:<20} {count:<25}")
            suspicious_activity_found = True
    if not suspicious_activity_found:
        print("No suspicious activity detected.")
    
    # Save results to a CSV file with a timestamped name to avoid overwriting
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f'log_analysis_results_{timestamp}.csv'
    
    logging.debug(f"Saving results to {output_file}")  # Debug
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
            for ip, count in failed_login_count.items():
                if count >= login_threshold:
                    writer.writerow([ip, count])
        else:
            writer.writerow(['No suspicious activity detected', ''])
    
    logging.debug(f"Results saved to {output_file}")  # Debug

# Main function to run the analysis
def main():
    logging.info("Starting log file analysis.")  # Info level log
    process_log_file(log_file_path)
    display_and_save_results()
    logging.info("Log file analysis complete.")  # Info level log

if __name__ == '__main__':
    main()
