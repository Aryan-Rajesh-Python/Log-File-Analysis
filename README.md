# Log File Analysis

This Python script processes and analyzes server log files to extract key insights such as IP request counts, most frequently accessed endpoints, and suspicious login attempts. It helps identify unusual patterns such as brute-force login attempts, and provides data for further investigation or reporting.

## Features

- **IP Request Count**: Counts the number of requests made by each IP address.
- **Endpoint Access Frequency**: Identifies the most frequently accessed endpoints (URLs or resource paths).
- **Failed Login Detection**: Detects suspicious activity by identifying IP addresses with failed login attempts (HTTP status 401 or "Invalid credentials") above a specified threshold.
- **Results Output**: Displays analysis results in a formatted console output and saves the data to a CSV file for further analysis.

## Requirements

- Python 3.x
- `re` (Regular Expressions)
- `csv` (for saving results)
- `collections.defaultdict` (for efficient counting)

## Installation and Usage

   ```bash
   git clone https://github.com/yourusername/log-file-analysis-tool.git
   python log_analysis.py
