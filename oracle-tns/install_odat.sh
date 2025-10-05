#!/bin/bash
# Robust installer for Oracle Instant Client + ODAT with persistent SQL*Plus

set -euo pipefail

BASIC_URL="https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip"
SQLPLUS_URL="https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip"
ORACLE_HOME="/opt/oracle/instantclient_21_4"

echo "[*] Updating system packages..."
sudo apt-get update -y || { echo "apt-get update failed"; exit 1; }

echo "[*] Installing system dependencies..."
sudo apt-get install -y unzip wget git python3 python3-pip \
    build-essential libgmp-dev python3-scapy || {
    echo "Failed to install system packages"; exit 1; }

echo "[*] Downloading Oracle Instant Client if missing..."
[ -f "instantclient-basic-linux.x64-21.4.0.0.0dbru.zip" ] || wget "$BASIC_URL"
[ -f "instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip" ] || wget "$SQLPLUS_URL"

echo "[*] Creating Oracle directory..."
sudo mkdir -p /opt/oracle

echo "[*] Extracting Oracle Instant Client..."
sudo unzip -o -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
sudo unzip -o -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip

echo "[*] Setting up persistent environment..."
# Profile script for all users
sudo tee /etc/profile.d/oracle.sh >/dev/null <<EOF
export ORACLE_HOME=$ORACLE_HOME
export LD_LIBRARY_PATH=$ORACLE_HOME:\${LD_LIBRARY_PATH:-}
export PATH=$ORACLE_HOME:\$PATH
EOF

sudo chmod +x /etc/profile.d/oracle.sh

# Add Oracle client libs to linker configuration
if [ ! -f /etc/ld.so.conf.d/oracle-instantclient.conf ]; then
    echo "$ORACLE_HOME" | sudo tee /etc/ld.so.conf.d/oracle-instantclient.conf
fi
sudo ldconfig

# Symlink sqlplus into /usr/bin for global accessibility
if [ ! -f /usr/bin/sqlplus ]; then
    sudo ln -s $ORACLE_HOME/sqlplus /usr/bin/sqlplus
fi

echo "[*] Cloning ODAT repository..."
cd ~
if [ ! -d "odat" ]; then
    git clone https://github.com/quentinhardy/odat.git
fi
cd odat

echo "[*] Initializing git submodules..."
git submodule init || true
git submodule update || true

echo "[*] Installing Python dependencies..."
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install cx_Oracle pycryptodome python-libnmap \
    colorlog termcolor passlib || {
    echo "Failed to install some Python packages"; exit 1; }

echo
echo "[+] ODAT setup complete!"
echo "    Run it with: cd ~/odat && python3 odat.py -h"
echo
echo "[*] Testing SQL*Plus..."
if command -v sqlplus >/dev/null; then
    sqlplus -v
    echo "[+] SQL*Plus is installed and available in PATH."
else
    echo "[!] SQL*Plus not found in PATH. Check /etc/profile.d/oracle.sh and ldconfig."
fi
