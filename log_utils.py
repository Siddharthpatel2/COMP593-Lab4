import re
import sys
import os
import csv

def get_file_path(param_num):
    if len(sys.argv) <= param_num:
        print(f"Error: No parameter {param_num} provided.")
        sys.exit(1)
    file_path = sys.argv[param_num]
    if not os.path.isfile(file_path):
        print(f"Error: The file {file_path} does not exist.")
        sys.exit(1)
    return file_path

def filter_log_by_regex(file_path, regex, case_sensitive=False, print_summary=False, print_records=False):
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(regex, flags)
    matched_records = []
    captured_data = []
    with open(file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                matched_records.append(line)
                captured_data.append(match.groups())
                if print_records:
                    print(line.strip())
    if print_summary:
        print(f"The log file contains {len(matched_records)} records that match the regex '{regex}'.")
    return matched_records, captured_data

def tally_port_traffic(file_path):
    port_tally = {}
    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(r'DPT=(\d+)', line)
            if match:
                port = match.group(1)
                if port in port_tally:
                    port_tally[port] += 1
                else:
                    port_tally[port] = 1
    return port_tally

def generate_port_traffic_report(file_path, port_number):
    report_filename = f"destination_port_{port_number}_report.csv"
    with open(file_path, 'r') as file, open(report_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port"])
        for line in file:
            if f"DPT={port_number}" in line:
                match = re.search(r'(\S+ \S+) (\S+) SRC=(\S+) DST=(\S+) .*SPT=(\S+) DPT=(\S+)', line)
                if match:
                    writer.writerow(match.groups())

def generate_invalid_user_report(file_path):
    report_filename = "invalid_users.csv"
    with open(file_path, 'r') as file, open(report_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Time", "Username", "IP Address"])
        for line in file:
            if "Invalid user" in line:
                match = re.search(r'(\S+ \S+) (\S+) Invalid user (\S+) from (\S+)', line)
                if match:
                    writer.writerow(match.groups())

def generate_source_ip_log(file_path, source_ip):
    output_filename = f"source_ip_{source_ip.replace('.', '_')}.log"
    with open(file_path)
