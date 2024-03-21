#!/bin/sh
##########################################
#                                        #
#   Configure installation parameters:   #
#                                        #
##########################################

PREFIX="${PREFIX:=/usr/local}"
EXECUTABLE_PATH="$PREFIX/bin/stonenetd"
CONFIG_PATH="$PREFIX/etc/stonenet"
DATA_FILES_PATH="$PREFIX/share/stonenet"
LOGFILE="$PREFIX/var/log/stonenet.log"
# Build & install the desktop app as well.
#USE_DESKTOP_APP=1
# If your system is using Systemd, just uncomment the following line to enable
# the Systemd service:
#SYSTEMD_PATH=/lib/systemd/system


##########################################
#                                        #
#   DO NOT CHANGE ANYTHING BELOW THIS!   #
#                                        #
##########################################

set -e
cargo build --release
if -n "$USE_DESKTOP_APP"; then
    cargo build -p stonenet-desktop --release
fi
install target/release/stonenetd "$EXECUTABLE_PATH"
if -n "$USE_DESKTOP_APP"; then
    install target/release/stonenet-desktop "$EXECUTABLE_PATH"
fi
install conf/base.toml "$CONFIG_PATH/config.toml"
install -t static "$DATA_FILES_PATH"
install -t templates "$DATA_FILES_PATH"
# Install systemd service by default
if -n "$SYSTEMD_PATH"; then
    install assets/generic/systemd/stonenetd.service "$SYSTEMD_PATH"
    systemctl enable --now stonenetd
    systemctl daemon-reload
    echo Installed systemd service.
# If $SYSTEMD_PATH is empty, try the XDG autostart folder
else
    if -n "$XDG_CONFIG_DIRS"; then
        install assets/generic/xdg/org.stonenet.stonenetd.desktop "$XDG_CONFIG_DIRS/autostart"
        echo Installed XDG autostart desktop entry.
    elif -d /etc/xdg/autostart; then
        install assets/generic/xdg/org.stonenet.stonenetd.desktop /etc/xdg/autostart"
        echo Installed XDG autostart desktop entry.
    else
        echo "Stonenet is not configured to run on system startup. You'll need to do this manually!"
    fi
fi