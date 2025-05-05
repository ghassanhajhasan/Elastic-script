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
FLEET_SERVER_URL="192.168.80.210"
FLEET_SERVER_PORT="8220"
ENROLLMENT_TOKEN="NGx1OGlKRUJYNXFpaUk1dldKcWM6Q3A4b0ljd3BUV1dPTm9aNlRyaGU1UQ=="
DEB_PACKAGE="elastic-agent-8.12.2-amd64.deb"
RPM_PACKAGE="elastic-agent-8.12.2-x86_64.rpm"
ELK_CERT="elasticsearch-ca.pem"
LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/install_Elastic-Agent_$(hostname -I | awk '{print $1}')_$(hostname).log"

# Redirect stdout and stderr to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

INSTALL_TIMEOUT=600  # Timeout for installation steps

# Function to log with timestamp
log_with_timestamp() {
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

# Function to test connectivity using curl
test_curl() {
  curl --silent --max-time 5 "$FLEET_SERVER_HOST:$FLEET_SERVER_PORT" &>/dev/null
}

# Function to test connectivity using telnet
test_telnet() {
  echo quit | telnet "$FLEET_SERVER_HOST" "$FLEET_SERVER_PORT" &>/dev/null
}

# Function to test connectivity using nc (Netcat)
test_nc() {
  nc -zv "$FLEET_SERVER_HOST" "$FLEET_SERVER_PORT" &>/dev/null
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

# Check for dependencies based on OS type
if [ "$IS_DEBIAN" = true ]; then
  for dep in dpkg ; do
    if ! command -v $dep &> /dev/null; then
      log_with_timestamp "${RED}[ERROR] Dependency $dep not found. Exiting.${NC}"
      exit 1
    fi
  done
  log_with_timestamp "${GREEN}[OK] All required dependencies are installed on Debian-based system.${NC}"
else
  for dep in rpm ; do
    if ! command -v $dep &> /dev/null; then
      log_with_timestamp "${RED}[ERROR] Dependency $dep not found. Exiting.${NC}"
      exit 1
    fi
  done
  log_with_timestamp "${GREEN}[OK] All required dependencies are installed on Red Hat-based system.${NC}"
fi

# Check if Elastic Agent is already installed
log_with_timestamp "${YELLOW}[INFO] Checking if Elastic Agent is already installed...${NC}"
if command -v elastic-agent &> /dev/null; then
  log_with_timestamp "${GREEN}[INFO] Elastic Agent is already installed.${NC}"
  
  # Ask user if they want to reinstall
  read -p "Do you want to reinstall Elastic Agent? (Y|N): " REINSTALL_CHOICE
  REINSTALL_CHOICE=$(echo "$REINSTALL_CHOICE" | tr '[:lower:]' '[:upper:]')
  
  if [[ "$REINSTALL_CHOICE" != "N" && "$REINSTALL_CHOICE" != "NO" ]]; then
    log_with_timestamp "${GREEN}[INFO] Skipping Elastic Agent installation.${NC}"
    exit 0
  fi
fi

# Check for available tools and test connectivity
log_with_timestamp "${YELLOW}[INFO] Checking if Fleet Server is reachable...${NC}"

if command -v curl &> /dev/null; then
  log_with_timestamp "${YELLOW}[INFO] Using curl to test connection...${NC}"
  if test_curl; then
    log_with_timestamp "${GREEN}[OK] Fleet Server is reachable on port ${FLEET_SERVER_PORT} using curl.${NC}"
  else
    log_with_timestamp "${RED}[ERROR] Fleet Server is not reachable on port ${FLEET_SERVER_PORT} using curl.${NC}"
    exit 1
  fi
elif command -v telnet &> /dev/null; then
  log_with_timestamp "${YELLOW}[INFO] Using telnet to test connection...${NC}"
  if test_telnet; then
    log_with_timestamp "${GREEN}[OK] Fleet Server is reachable on port ${FLEET_SERVER_PORT} using telnet.${NC}"
  else
    log_with_timestamp "${RED}[ERROR] Fleet Server is not reachable on port ${FLEET_SERVER_PORT} using telnet.${NC}"
    exit 1
  fi
elif command -v nc &> /dev/null; then
  log_with_timestamp "${YELLOW}[INFO] Using nc (Netcat) to test connection...${NC}"
  if test_nc; then
    log_with_timestamp "${GREEN}[OK] Fleet Server is reachable on port ${FLEET_SERVER_PORT} using nc.${NC}"
  else
    log_with_timestamp "${RED}[ERROR] Fleet Server is not reachable on port ${FLEET_SERVER_PORT} using nc.${NC}"
    exit 1
  fi
else
  log_with_timestamp "${RED}[ERROR] No suitable tool (curl, telnet, or nc) found for testing connectivity.${NC}"
  read -p "Do you want to continue without testing the connectivity? (Y|N): " CONTINUE_CHOICE
  CONTINUE_CHOICE=$(echo "$CONTINUE_CHOICE" | tr '[:lower:]' '[:upper:]')

  if [[ "$CONTINUE_CHOICE" == "Y" || "$CONTINUE_CHOICE" == "YES" ]]; then
    log_with_timestamp "${YELLOW}[INFO] Proceeding without connectivity test.${NC}"
  else
    log_with_timestamp "${RED}[ERROR] Exiting as no suitable tool is available to test connectivity.${NC}"
    exit 1
  fi
fi

# Check if the appropriate installation file exists
log_with_timestamp "${YELLOW}[INFO] Checking if the installation file exists...${NC}"
if [ "$IS_DEBIAN" = true ]; then
  if [ ! -f "$DEB_PACKAGE" ]; then
    log_with_timestamp "${RED}[ERROR] Debian installation package $DEB_PACKAGE not found. Exiting.${NC}"
    exit 1
  fi
elif [ "$IS_DEBIAN" = false ]; then
  if [ ! -f "$RPM_PACKAGE" ]; then
    log_with_timestamp "${RED}[ERROR] RPM installation package $RPM_PACKAGE not found. Exiting.${NC}"
    exit 1
  fi
fi

# Install and configure Elastic Agent
log_with_timestamp "${YELLOW}[INFO] Installing Elastic Agent...${NC}"
if [ "$IS_DEBIAN" = true ]; then
  timeout $INSTALL_TIMEOUT dpkg -i "$DEB_PACKAGE" || { log_with_timestamp "${RED}[ERROR] Failed to install Elastic Agent (Debian/Ubuntu). Exiting.${NC}"; exit 1; }
else
  timeout $INSTALL_TIMEOUT rpm -ivh "$RPM_PACKAGE" || { log_with_timestamp "${RED}[ERROR] Failed to install Elastic Agent (RHEL/CentOS). Exiting.${NC}"; exit 1; }
fi

# Check if Elastic Agent was installed successfully
log_with_timestamp "${YELLOW}[INFO] Checking if Elastic Agent is installed...${NC}"
if command -v elastic-agent &> /dev/null; then
  log_with_timestamp "${GREEN}[OK] Elastic Agent installed successfully.${NC}"
else
  log_with_timestamp "${RED}[ERROR] Elastic Agent installation failed. Exiting.${NC}"
  exit 1
fi

# Check if the elasticsearch-ca.pem file exists
log_with_timestamp "${YELLOW}[INFO] Checking if Elasticsearch CA certificate exists...${NC}"
if [ ! -f "$ELK_CERT" ]; then
  log_with_timestamp "${RED}[ERROR] Elasticsearch CA certificate $ELK_CERT not found. Exiting.${NC}"
  exit 1
fi

# Enroll Elastic Agent with Fleet Server
log_with_timestamp "${YELLOW}[INFO] Enrolling Elastic Agent with Fleet Server...${NC}"
elastic-agent enroll --url="${FLEET_SERVER_URL}:${FLEET_SERVER_PORT}" --enrollment-token="$ENROLLMENT_TOKEN" --certificate-authorities="$ELK_CERT" || { log_with_timestamp "${RED}[ERROR] Failed to enroll Elastic Agent. Exiting.${NC}"; exit 1; }

if command -v systemctl &> /dev/null; then
  systemctl enable elastic-agent
  systemctl start elastic-agent
else
  service elastic-agent start
  chkconfig elastic-agent on
fi

log_with_timestamp "${GREEN}[OK] Elastic Agent installed and enrolled.${NC}"
