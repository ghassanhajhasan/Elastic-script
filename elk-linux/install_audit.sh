#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Trap for better error messages
trap 'echo -e "$(date "+%Y-%m-%d %H:%M:%S") ${RED}[ERROR] Command \"${BASH_COMMAND}\" failed at line ${LINENO}.${NC}"' ERR

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables
AUDIT_DEP_FILE="audit-dep.rules"
AUDIT_RPM_FILE="audit-rpm.rules"
LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/install_audit_$(hostname -I | awk '{print $1}')_$(hostname).log"

# Redirect stdout and stderr to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

INSTALL_TIMEOUT=600  # Timeout for installation steps

# Function to log with timestamp
log_with_timestamp() {
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

# Detect the OS type
log_with_timestamp "${YELLOW}[INFO] Detecting OS type...${NC}"
if [ -f /etc/debian_version ]; then
  log_with_timestamp "${GREEN}[OK] Debian-based OS detected.${NC}"
  IS_DEBIAN=true
elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
  log_with_timestamp "${GREEN}[OK] Red Hat-based OS detected.${NC}"
  IS_DEBIAN=false
else
  log_with_timestamp "${RED}[ERROR] Unsupported OS. Exiting.${NC}"
  exit 1
fi

# Check if audit package is installed
log_with_timestamp "${YELLOW}[INFO] Checking if audit package is installed...${NC}"
if ! rpm -q audit &> /dev/null && ! dpkg -l | grep -q audit; then
  log_with_timestamp "${RED}[ERROR] Audit package not found. Attempting installation...${NC}"

  # Install audit package based on OS
  if [ "$IS_DEBIAN" = true ]; then
    if command -v apt-get &> /dev/null; then
      log_with_timestamp "${YELLOW}[INFO] Using apt-get to install audit package...${NC}"
      apt-get update && apt-get install -y auditd || { log_with_timestamp "${RED}[ERROR] Failed to install audit package using apt-get. Please install it manually. Exiting.${NC}"; exit 1; }
    elif command -v apt &> /dev/null; then
      log_with_timestamp "${YELLOW}[INFO] Using apt to install audit package...${NC}"
      apt update && apt install -y auditd || { log_with_timestamp "${RED}[ERROR] Failed to install audit package using apt. Please install it manually. Exiting.${NC}"; exit 1; }
    else
      log_with_timestamp "${RED}[ERROR] Neither apt-get nor apt is available. Please install auditd manually. Exiting.${NC}"
      exit 1
    fi
  else
    log_with_timestamp "${YELLOW}[INFO] Using yum to install audit package...${NC}"
    yum install -y audit || { log_with_timestamp "${RED}[ERROR] Failed to install audit package using yum. Please install it manually. Exiting.${NC}"; exit 1; }
  fi
  log_with_timestamp "${GREEN}[OK] Audit package installed.${NC}"
else
  log_with_timestamp "${GREEN}[OK] Audit package is already installed.${NC}"
fi

# Apply audit rules
log_with_timestamp "${YELLOW}[INFO] Applying audit rules...${NC}"
if [ "$IS_DEBIAN" = true ]; then
  cp "$AUDIT_DEP_FILE" /etc/audit/rules.d/ || { log_with_timestamp "${RED}[ERROR] Failed to copy audit rules. Exiting.${NC}"; exit 1; }
else
  cp "$AUDIT_RPM_FILE" /etc/audit/rules.d/ || { log_with_timestamp "${RED}[ERROR] Failed to copy audit rules. Exiting.${NC}"; exit 1; }
fi
log_with_timestamp "${GREEN}[OK] Audit rules applied successfully.${NC}"

# Modify /etc/audit/auditd.conf to set name_format to HOSTNAME
log_with_timestamp "${YELLOW}[INFO] Modifying /etc/audit/auditd.conf to set name_format to HOSTNAME...${NC}"
sed -i 's/^name_format = NONE/name_format = HOSTNAME/' /etc/audit/auditd.conf || { log_with_timestamp "${RED}[ERROR] Failed to modify auditd.conf. Exiting.${NC}"; exit 1; }
log_with_timestamp "${GREEN}[OK] /etc/audit/auditd.conf modified successfully.${NC}"

# Fix the RefuseManualStop issue
fix_auditd_manual_stop() {
  log_with_timestamp "${YELLOW}[INFO] Checking for RefuseManualStop issue with auditd...${NC}"
  AUDITD_SERVICE_FILE="/usr/lib/systemd/system/auditd.service"
  if grep -q "RefuseManualStop=yes" "$AUDITD_SERVICE_FILE"; then
    log_with_timestamp "${YELLOW}[INFO] Found RefuseManualStop set to yes. Changing to no...${NC}"
    sed -i 's/RefuseManualStop=yes/RefuseManualStop=no/' "$AUDITD_SERVICE_FILE"
    systemctl daemon-reload
  fi
}

# Function to restore the RefuseManualStop setting after actions are completed
restore_auditd_manual_stop() {
  log_with_timestamp "${YELLOW}[INFO] Restoring RefuseManualStop setting to yes...${NC}"
  sed -i 's/RefuseManualStop=no/RefuseManualStop=yes/' "/usr/lib/systemd/system/auditd.service"
  systemctl daemon-reload
}

# Fix the RefuseManualStop issue, restart auditd, then restore the setting
fix_auditd_manual_stop  # Fix the RefuseManualStop issue before restarting the service

# Restart auditd to apply changes
log_with_timestamp "${YELLOW}[INFO] Restarting auditd to apply changes...${NC}"
systemctl restart auditd || { log_with_timestamp "${RED}[ERROR] Failed to restart auditd. Exiting.${NC}"; exit 1; }
log_with_timestamp "${GREEN}[OK] auditd restarted successfully.${NC}"

restore_auditd_manual_stop  # Restore RefuseManualStop setting to yes after restarting auditd

# Final Success Message
log_with_timestamp "${GREEN}[INFO] Audit Installation and configuration completed successfully.${NC}"
