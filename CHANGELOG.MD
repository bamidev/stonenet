# Changes since 0.5.0
* Added a Nix flake that includes modules for NixOS and home-manager users.
* We now log to journalctl rather than a seperate log file.
* Use the first free port that is found when any of the UDP or TCP ports are set to 0.
* Use an user-level config file if available. (At ~/.config/stonenet/config.toml)
* Fixed a concurrency bug when initiating a connection with another node 'in reverse'.
* Increased the file upload limit of the client from 2MB to 10MB.
* Disabled the 'upgrade instructions' for Debian packages and Nix modules.
