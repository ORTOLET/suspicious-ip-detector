#!/bin/bash

# Log file (for testing)
LOG_FILE="test_logs.log"
SUSPICIOUS_REPORT="suspicious_ips.txt"  # Output report file

echo "Processing file: $LOG_FILE"

# Check if file exists
if [ ! -f "$LOG_FILE" ]; then
    echo "Warning: file $LOG_FILE not found, skipping."
    exit 1
fi

# Print the log content for debugging
echo "Contents of $LOG_FILE:"
cat "$LOG_FILE"

# Extract suspicious events and IPs, and save to temporary report file
TEMP_REPORT="temp_report.txt"
> "$TEMP_REPORT"

# Check for failed login attempts and extract IPs
echo "Extracting IPs from 'Failed password' or other login attempts..."
grep -iE "Failed|unauthorized|invalid|error|sshd" "$LOG_FILE" | \
tee /dev/tty | \
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
awk '{print $1, "(Authentication/SSH attempt)"}' >> "$TEMP_REPORT"

# Check for kernel/system warnings and extract IPs
echo "Extracting IPs from kernel/system warnings..."
grep -iE "security|warning|intrusion|unauthorized|error" "$LOG_FILE" | \
tee /dev/tty | \
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
awk '{print $1, "(Kernel/System warning)"}' >> "$TEMP_REPORT"

# Check for unauthorized cron job attempts and extract IPs
echo "Extracting IPs from unauthorized cron job attempts..."
grep -i "unauthorized" "$LOG_FILE" | \
tee /dev/tty | \
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
awk '{print $1, "(Unauthorized cron job)"}' >> "$TEMP_REPORT"

# Check if we have data in the report file
echo "Checking if suspicious IPs have been added to the report..."
cat "$TEMP_REPORT"  # This should show us the content of the report

# Ensure the temporary file is not empty
if [ -s "$TEMP_REPORT" ]; then
    echo "Counting occurrences of IP-method pairs..."
    temp_report=$(mktemp)  # Create a temporary file for sorting

    # Count occurrences and sort the results
    sort "$TEMP_REPORT" | uniq -c | sort -nr > "$temp_report"

    # Check if sorting and counting worked correctly
    if [ -s "$temp_report" ]; then
        # Move the sorted report to the final report file
        mv "$temp_report" "$SUSPICIOUS_REPORT"
    else
        echo "Warning: Failed to sort and count IP-method pairs."
    fi
else
    echo "No suspicious IP-method pairs found."
fi

# Output the suspicious IPs and connection methods with counts
echo "Suspicious IPs and connection methods (with counts):"
cat "$SUSPICIOUS_REPORT"

# Clean up temporary report
rm "$TEMP_REPORT"

echo "Analysis completed. Detailed report saved to $SUSPICIOUS_REPORT."
