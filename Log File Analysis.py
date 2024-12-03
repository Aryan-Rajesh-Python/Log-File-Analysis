import re
import csv
from collections import defaultdict

# Define the log file path
log_file_path = 'sample.log'

# Initialize data structures to store results
ip_requests = defaultdict(int)
endpoint_access = defaultdict(int)
failed_login_count = defaultdict(int)

# Define the threshold for suspicious activity (failed logins)
login_threshold = 3  # Adjust this to the desired threshold (e.g., 3)

# Define a function to process the log file
def process_log_file(log_file_path):
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.match(r'(\S+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1

            # Extract endpoint (e.g., URL or resource path)
            endpoint_match = re.search(r'"(GET|POST|PUT|DELETE) (\S+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(2)
                endpoint_access[endpoint] += 1

            # Detect failed login attempts (HTTP status code 401 or "Invalid credentials")
            if '401' in line or 'Invalid credentials' in line:
                ip_failed_match = re.match(r'(\S+)', line)
                if ip_failed_match:
                    ip_failed = ip_failed_match.group(1)
                    failed_login_count[ip_failed] += 1

# Function to display and save results
def display_and_save_results():
    # 1. Requests per IP Address
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    # 2. Most Frequently Accessed Endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1], default=("None", 0))
    print(f"\nMost Frequently Accessed Endpoint:")
    print(f"Endpoint: {most_accessed_endpoint[0]}, Access Count: {most_accessed_endpoint[1]}")
    
    # 3. Suspicious Activity (Failed login attempts above threshold)
    print(f"\nSuspicious Activity Detected (Failed Logins Above {login_threshold}):")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    suspicious_activity_found = False  # Flag to check if we found any suspicious activity
    for ip, count in failed_login_count.items():
        if count >= login_threshold:
            print(f"{ip:<20} {count}")
            suspicious_activity_found = True
    
    # Save results to a CSV file in the exact format
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP Address
        writer.writerow(['Requests per IP Address:'])
        writer.writerow(['IP Address'.center(20), 'Request Count'.center(20)])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip.center(20), str(count).center(20)])

        # Add some blank rows for visual separation
        writer.writerow([])
        
        # Most Accessed Endpoint
        writer.writerow(['Most Frequently Accessed Endpoint:'])
        writer.writerow(['Endpoint'.center(20), 'Access Count'.center(20)])
        writer.writerow([most_accessed_endpoint[0].center(20), str(most_accessed_endpoint[1]).center(20)])

        # Add some blank rows for visual separation
        writer.writerow([])

        # Write Suspicious Activity header
        writer.writerow(['Suspicious Activity Detected (Failed Logins Above 3):'])
        writer.writerow(['IP Address'.center(20), 'Failed Login Attempts'.center(20)])

        # Write failed login attempts to CSV
        if suspicious_activity_found:
            for ip, count in failed_login_count.items():
                if count >= login_threshold:
                    writer.writerow([ip.center(20), str(count).center(20)])
        else:
            # If no suspicious activity is found, write a placeholder
            writer.writerow(['No suspicious activity detected'.center(20), ''])

# Main function to run the analysis
def main():
    process_log_file(log_file_path)
    display_and_save_results()

if __name__ == '__main__':
    main()