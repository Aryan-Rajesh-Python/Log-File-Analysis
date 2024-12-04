# Log File Analysis

This Python script analyzes log files to extract valuable insights such as IP address activity, endpoint access patterns, and failed login attempts. It processes log files efficiently by utilizing multithreading and chunk-based processing. The results are displayed on the console and saved into a timestamped CSV file for further analysis.

## Features

- **Log file processing**: Handles log files in chunks to optimize memory and processing speed.
- **IP Address Tracking**: Tracks the number of requests made by each IP address.
- **Endpoint Access Monitoring**: Identifies the most frequently accessed endpoints.
- **Suspicious Activity Detection**: Flags IP addresses with failed login attempts exceeding a user-defined threshold.
- **Multithreading**: Uses multithreading for efficient log file processing across multiple CPU cores.
- **Rotating logs**: The script logs events in a rotating log file to prevent large log file accumulation.
- **Customizable Configuration**: Supports configuration via command-line arguments for login attempt thresholds and chunk sizes.

## Requirements

- Python 3.x
- Required Python libraries:
  - `re` (Regex)
  - `csv` (CSV file handling)
  - `logging` (Logging functionality)
  - `threading` (Multithreading)
  - `argparse` (Command-line argument parsing)
  - `os` (Operating system interaction)
  - `collections` (Data structures like `defaultdict`)
  - `datetime` (Timestamp handling)
  - `concurrent.futures` (Thread pool for parallel processing)
  - `logging.handlers` (Rotating file handler for logs)

## Installation and Usage

   ```bash
   git clone https://github.com/Aryan-Rajesh-Python/Log-File-Analysis.git
   python Log File Analysis.py  (or)  python Log File Analysis.py --login-threshold 5 --chunk-size 500
