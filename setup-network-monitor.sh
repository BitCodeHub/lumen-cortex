#!/bin/bash
# Lumen Cortex - Network Monitor Setup Script
# This script enables real-time network monitoring without requiring password each time

echo "🛡️ Lumen Cortex Network Monitor Setup"
echo "======================================"
echo ""
echo "This will configure your system for real-time device monitoring."
echo "You'll need to enter your password once to set this up."
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "❌ Don't run this script with sudo. Run it normally and enter password when prompted."
    exit 1
fi

# Get current user
CURRENT_USER=$(whoami)

echo "Setting up passwordless tcpdump for user: $CURRENT_USER"
echo ""

# Create sudoers entry for tcpdump
SUDOERS_LINE="$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump"

# Check if already configured
if sudo grep -q "NOPASSWD.*tcpdump" /etc/sudoers.d/tcpdump 2>/dev/null; then
    echo "✅ Network monitoring is already configured!"
else
    echo "Creating sudo rule for tcpdump..."
    echo "$SUDOERS_LINE" | sudo tee /etc/sudoers.d/tcpdump > /dev/null
    sudo chmod 440 /etc/sudoers.d/tcpdump
    
    # Validate sudoers file
    if sudo visudo -c -f /etc/sudoers.d/tcpdump 2>/dev/null; then
        echo "✅ Successfully configured!"
    else
        echo "❌ Configuration failed. Removing invalid file..."
        sudo rm -f /etc/sudoers.d/tcpdump
        exit 1
    fi
fi

# Test that it works
echo ""
echo "Testing network capture..."
if sudo tcpdump -i en0 -c 1 -n 2>/dev/null | grep -q ""; then
    echo "✅ Network capture is working!"
else
    echo "⚠️ Test capture returned no packets (this is OK if no traffic)"
fi

echo ""
echo "======================================"
echo "✅ Setup complete!"
echo ""
echo "You can now use real-time device monitoring in Lumen Cortex."
echo "Restart the server: pm2 restart lumen-cortex"
echo ""
