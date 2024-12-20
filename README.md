# Suspicious IP Detector

This is a bash script designed to analyze system log files and detect suspicious activities related to security incidents. 
The script is primarily intended for **Security Operations Center (SOC) analysts** to identify and investigate potentially malicious behavior based on log files from systems.

## Purpose
The script scans system logs for suspicious activities. You can find the repository and more details [here](https://github.com/ORTOLET/suspicious-ip-detector).
- **Failed SSH login attempts** (which may indicate brute-force attacks).
- **Kernel/system warnings** (which could suggest intrusion attempts or abnormal system behavior).
- **Unauthorized cron job attempts** (indicating possible attempts to schedule malicious tasks).
- It then aggregates and reports **suspicious IP addresses** involved in these activities.

## Features
- Detects **failed SSH login attempts**.
- Flags **suspicious kernel/system warnings**.
- Identifies **unauthorized cron job attempts**.
- Outputs a detailed list of suspicious IPs and activities in a file called `suspicious_ips.txt`.

## Usage

### How to use the script:
1. **Clone the repository**:
     Clone the repository to your local machine using Git:
     ```bash
     git clone https://github.com/ORTOLET/suspicious-ip-detector.git
     cd suspicious-ip-detector
     ```

2. **Make the script executable**:
     Ensure that the script is executable by running:
     ```bash
     chmod +x kinnamon.sh
     ```

3. **Run the script**:
     Execute the script with your desired log file as an argument:
     ```bash
     sudo ./kinnamon.sh /path/to/your/logfile.log
     ```
     Replace `/path/to/your/logfile.log` with the actual path to the system log file you want to analyze (e.g., `/var/log/auth.log`).

4. **Check the output**:
     The script will generate a file called `suspicious_ips.txt`, which contains a list of suspicious IPs and the activities associated with them.

## Requirements
   - Linux-based system
   - Utilities: `grep`, `awk`, `sort`

## Example

Here’s an example of how to run the script on a system log file:

1. **Clone the repository**:
   ```bash
      git clone https://github.com/ORTOLET/suspicious-ip-detector.git
      cd suspicious-ip-detector
   
2. **Make the script executable**
     chmod +x kinnamon.sh
   
4. **Run the script on a log file**:
     sudo ./kinnamon.sh /var/log/auth.log
   
5. **Check the output**:
     The script will generate a file called suspicious_ips.txt:
     203.0.113.10 (SSH login attempt)
     192.168.1.5 (Kernel/system warning)
     198.51.100.1 (Unauthorized cron job)

     


## License
   This project is licensed under the MIT License

