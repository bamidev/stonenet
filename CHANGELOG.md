# Changelog

## v0.7.1
* Changed the block size for newly created files to 16 MiB.
* Fixed an issue with object synchronization when obtaining a new head object.
* Fixed block size verification when loading them from the database.

## v0.7.0
* Cleared all identities and blogchain data from the database because of a significant change to the data format of the blogchain.
  This is in preparation to be able to host websites on Stonenet in the future.
* Relay messages will not leak the 'relay-hello' packet if the relay node was configured to leak the first request.
* Fixed a bug where different DH private keys where used when a (relay)-hello packet was sent a second time or more.
* Stopped using the 'hello-ack-ack' packet for SSTP connection establishment.
* Fixed a bug where packages where sent to a relay when relaying between UDP & TCP, that were to big for UDP.
* When the database file path in the configuration file starts with "~/", it will be resolved to the running user's home directory.
* Store the private keys of identities in XDG_DATA /var/lib/stonenet/identity, or in XDG_DATA_HOME or ~/.local/share/stonenet/identity if the system user name has been provided as a cookie.
* Only show identities created for a specific system user to that specific system user.
* The systemd service now runs stonenet as the stonenet user, unless using it through home-manager.
* Fixed IPv6 communication on Windows.
