#!/bin/bash

# Default log files
DEFAULT_LOG_FILES=("/var/log/auth.log" "/var/log/access.log" "/var/log/kern.log" "/var/log/cron.log")
SUSPICIOUS_REPORT="suspicious_ips.txt"  # Output report file
DEBUG=false  # Set to true for debug output

# Check if a specific log file is passed as an argument, otherwise use default files
LOG_FILES=("${@:-${DEFAULT_LOG_FILES[@]}}")

echo "Processing log files: ${LOG_FILES[@]}"

# Create/clear the suspicious IP report file
> "$SUSPICIOUS_REPORT"

# Function to extract suspicious IPs from logs
extract_ips() {
    local log_file="$1"
    local patterns="$2"
    local label="$3"

    grep -iE "$patterns" "$log_file" | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    awk -v label="$label" '{print $1, label}'
}

# Define patterns for each category
declare -A PATTERNS=(
    ["Authentication/SSH attempt"]="Failed|unauthorized|invalid|error|sshd"
    ["Kernel/System warning"]="security|warning|intrusion|unauthorized|error"
    ["Unauthorized cron job"]="unauthorized"
)

# Process each log file
for LOG_FILE in "${LOG_FILES[@]}"; do
    echo "Processing file: $LOG_FILE"

    # Check if file exists
    if [ ! -f "$LOG_FILE" ]; then
        echo "Warning: File $LOG_FILE not found, skipping."
        continue
    fi

    # Extract IPs for each category
    for label in "${!PATTERNS[@]}"; do
        $DEBUG && echo "Extracting IPs: $label..."
        extract_ips "$LOG_FILE" "${PATTERNS[$label]}" "($label)" >> "$SUSPICIOUS_REPORT.tmp"
    done
done

# Post-process the temporary report
if [ -s "$SUSPICIOUS_REPORT.tmp" ]; then
    # Count unique pairs and sort by frequency
    sort "$SUSPICIOUS_REPORT.tmp" | uniq -c | sort -nr > "$SUSPICIOUS_REPORT"
    rm "$SUSPICIOUS_REPORT.tmp"
else
    echo "No suspicious IPs found."
fi

# Output the suspicious IPs and connection methods with counts
echo "Suspicious IPs and connection methods (with counts):"
cat "$SUSPICIOUS_REPORT"

echo "Analysis completed. Detailed report saved to $SUSPICIOUS_REPORT."
