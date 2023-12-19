#!/bin/sh
EXECUTABLE_PATH=/usr/local/bin/stonenet
CONFIG_PATH=/usr/local/etc/stonenet
DATA_FILES_PATH=/usr/local/share/stonenet
LOGFILE=/var/log/stonenet.log
# If your system is not using Systemd, just comment out this following line
SYSTEMD_PATH=/lib/systemd/system



set -e
cargo build --release
install target/release/stonenetd "$EXECUTABLE_PATH"
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
fi