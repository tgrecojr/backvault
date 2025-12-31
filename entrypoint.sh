#!/bin/bash
set -euo pipefail

echo "Initializing BackVault backup service"

# Validate BACKUP_INTERVAL_HOURS
BACKUP_INTERVAL_HOURS=${BACKUP_INTERVAL_HOURS:-12}
if ! [[ "$BACKUP_INTERVAL_HOURS" =~ ^[1-9][0-9]*$ ]] || [ "$BACKUP_INTERVAL_HOURS" -gt 8760 ]; then
    echo "ERROR: BACKUP_INTERVAL_HOURS must be a positive integer between 1 and 8760 (1 year)"
    exit 1
fi

# Convert hours to seconds for sleep
BACKUP_INTERVAL_SECONDS=$((BACKUP_INTERVAL_HOURS * 3600))

# Log file for backup operations
LOG_FILE=${LOG_FILE:-/var/log/cron.log}
touch "$LOG_FILE"

# Function to run backup
run_backup() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting backup..."
    python /app/run.py 2>&1 | tee -a "$LOG_FILE"
    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup completed successfully"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup failed with exit code $exit_code"
    fi
    return $exit_code
}

# Function to run cleanup
run_cleanup() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Running cleanup..."
    /app/cleanup.sh 2>&1 | tee -a "$LOG_FILE"
    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Cleanup completed successfully"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Cleanup failed with exit code $exit_code"
    fi
    return $exit_code
}

# Trap SIGTERM and SIGINT for graceful shutdown
shutdown() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Received shutdown signal, exiting gracefully..."
    exit 0
}

trap shutdown SIGTERM SIGINT

# Run initial backup immediately on startup
echo "Running initial backup on startup..."
run_backup || true

# Calculate seconds until midnight for daily cleanup
# Alpine uses busybox date, so we calculate midnight manually
seconds_until_midnight() {
    local current_epoch=$(date +%s)
    local current_hour=$(date +%H)
    local current_min=$(date +%M)
    local current_sec=$(date +%S)
    local seconds_since_midnight=$((current_hour * 3600 + current_min * 60 + current_sec))
    local seconds_until_midnight=$((86400 - seconds_since_midnight))
    echo $seconds_until_midnight
}

# Track last cleanup time
last_cleanup_day=$(date +%j)

# Main loop
echo "Starting backup loop with interval of $BACKUP_INTERVAL_HOURS hours ($BACKUP_INTERVAL_SECONDS seconds)"
while true; do
    # Sleep for the backup interval
    sleep "$BACKUP_INTERVAL_SECONDS" &
    wait $!

    # Run backup
    run_backup || true

    # Check if we need to run cleanup (once per day at midnight)
    current_day=$(date +%j)
    if [ "$current_day" != "$last_cleanup_day" ]; then
        run_cleanup || true
        last_cleanup_day=$current_day
    fi
done
