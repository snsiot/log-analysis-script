import re
import csv
from collections import defaultdict, Counter

# Function to parse the log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Function to count requests per IP address
def count_requests_per_ip(logs):
    ip_counts = Counter()
    for log in logs:
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

# Function to find the most frequently accessed endpoint
def find_most_accessed_endpoint(logs):
    endpoint_counts = Counter()
    for log in logs:
        match = re.search(r'"(?:GET|POST|PUT|DELETE) (\S+)', log)
        if match:
            endpoint_counts[match.group(1)] += 1
    most_common = endpoint_counts.most_common(1)
    return most_common[0] if most_common else (None, 0)

# Function to detect suspicious activity
def detect_suspicious_activity(logs, threshold=10):
    failed_login_attempts = Counter()
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                failed_login_attempts[match.group(1)] += 1
    return {ip: count for ip, count in failed_login_attempts.items() if count > threshold}

# Function to save results to CSV
def save_to_csv(ip_counts, most_accessed, suspicious_activity, output_file="log_analysis_results.csv"):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Add a blank line

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  # Add a blank line

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file = "sample.log"
    logs = parse_log_file(log_file)

    # Analyze log data
    ip_counts = count_requests_per_ip(logs)
    most_accessed = find_most_accessed_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_counts.items():
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")

    # Save results to CSV
    save_to_csv(ip_counts, most_accessed, suspicious_activity)

if __name__ == "__main__":
    main()
