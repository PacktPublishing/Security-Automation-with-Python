import re
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt

# Function to read log file
def read_log_file(file_path):
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        return logs
    except FileNotFoundError:
        print(f"Error: Log file {file_path} not found.")
        return []

# Function to parse logs using regex
def parse_logs(logs):
    log_data = []
    log_pattern = re.compile(
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\d+)'
    )
    for log in logs:
        match = log_pattern.search(log)
        if match:
            log_data.append(match.groupdict())
    return log_data

# Function to analyze log data
def analyze_logs(parsed_logs):
    df = pd.DataFrame(parsed_logs)
   
    # Convert size to numeric for analysis
    df['size'] = pd.to_numeric(df['size'], errors='coerce')
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
   
    # Basic statistics
    print("\n--- Basic Statistics ---")
    print(f"Total Requests: {len(df)}")
    print(f"Unique IPs: {df['ip'].nunique()}")
    print(f"Most Frequent Status Codes:\n{df['status'].value_counts()}")
   
    # Large requests
    large_requests = df[df['size'] > 1000000]
    print(f"\nLarge Requests (>1MB): {len(large_requests)}")
   
    return df

# Function to visualize data
def visualize_data(df):
    # Plot request distribution by status code
    status_counts = df['status'].value_counts()
    status_counts.plot(kind='bar', title='Requests by Status Code', xlabel='Status Code', ylabel='Count')
    plt.show()
   
    # Plot top 10 IPs by request count
    ip_counts = Counter(df['ip'])
    top_ips = dict(ip_counts.most_common(10))
    plt.bar(top_ips.keys(), top_ips.values())
    plt.title('Top 10 IPs by Request Count')
    plt.xlabel('IP Address')
    plt.ylabel('Request Count')
    plt.xticks(rotation=45)
    plt.show()

# Function to save analysis results
def save_analysis_results(df, output_path):
    try:
        df.to_csv(output_path, index=False)
        print(f"Analysis results saved to {output_path}")
    except Exception as e:
        print(f"Error saving file: {e}")

# Main function
def main():
    file_path = 'access.log'  # Replace with your log file path
    output_path = 'log_analysis_results.csv'
   
    logs = read_log_file(file_path)
    if not logs:
        return
   
    parsed_logs = parse_logs(logs)
    if not parsed_logs:
        print("No valid log entries found.")
        return
   
    df = analyze_logs(parsed_logs)
    visualize_data(df)
    save_analysis_results(df, output_path)

if __name__ == "__main__":
    main()
