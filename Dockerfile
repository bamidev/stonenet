FROM debian:trixie-slim

# Install debian packages
ENV DEBIAN_FRONTED=noninteractive
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y --no-install-recommends \
	gcc ca-certificates curl git libclang-dev pkg-config xz-utils

# Install Nix in order to get rustup & nuget
RUN mkdir -m 0755 /nix
RUN useradd -m stonenet
RUN chown stonenet /nix
USER stonenet
WORKDIR /home/stonenet
RUN curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install -o install-nix.sh; chmod +x install-nix.sh
RUN ./install-nix.sh --no-daemon
ENV PATH="/home/stonenet/.nix-profile/bin:${PATH}"
RUN nix-env -iA nixpkgs.rustup

# Clone Stonenet
ADD --chown=stonenet:stonenet . /home/stonenet/stonenet
WORKDIR stonenet
# This is not needed for Windows, but it is usefull that it's cached by docker
RUN cargo install cargo-deb

# After this, all stuff is target platform specific and so docker's cache can't really help a lot here

ARG target

# Get the WebView2 dll for Windows
RUN if [ $target = "win64" ]; then nix-env -iA nixpkgs.dotnetPackages.Nuget; fi
RUN if [ $target = "win64" ]; then nuget install Microsoft.Web.WebView2; fi

USER root
RUN if [ $target = "amd64" ]; then dpkg --add-architecture "amd64"; fi
RUN if [ $target = "arm64" ]; then dpkg --add-architecture "arm64"; fi
RUN if [ $target = "armhf" ]; then dpkg --add-architecture "armhf"; fi
RUN apt-get update
RUN if [ $target = "amd64" ]; then apt-get install -y --no-install-recommends \
	gcc-x86-64-linux-gnu libssl-dev:amd64 libsqlite3-dev:amd64 libwebkit2gtk-4.1-dev:amd64; fi
RUN if [ $target = "arm64" ]; then apt-get install -y --no-install-recommends \
	gcc-aarch64-linux-gnu libssl-dev:arm64 libsqlite3-dev:arm64 libwebkit2gtk-4.1-dev:arm64; fi
RUN if [ $target = "armhf" ]; then apt-get install -y --no-install-recommends \
	gcc-arm-linux-gnueabihf libssl-dev:armhf libsqlite3-dev:armhf libwebkit2gtk-4.1-dev:armhf; fi
RUN if [ $target = "win64" ]; then apt-get install -y --no-install-recommends \
	gcc-mingw-w64 nsis; fi

# Configure & install anything necessary for Rust
USER stonenet
RUN if [ $target = "amd64" ]; then rustup target add x86_64-unknown-linux-gnu; fi
RUN if [ $target = "arm64" ]; then rustup target add aarch64-unknown-linux-gnu; fi
RUN if [ $target = "armhf" ]; then rustup target add armv7-unknown-linux-gnueabihf; fi
RUN if [ $target = "win64" ]; then rustup target add x86_64-pc-windows-gnu; fi

# Compile packages for all the supported architectures
RUN mkdir ../out
#ENV BINDGEN_EXTRA_CLANG_ARGS_X86_64_PC_WINDOWS_GNU="-I/usr/lib/gcc/x86_64-w64-mingw32/14-win32/include"
# FIXME: The above does not work
ENV BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-w64-mingw32/14-win32/include"
RUN if [ $target = "win64" ]; then cargo build -p stonenet-desktop --release --target x86_64-pc-windows-gnu; fi
RUN if [ $target = "win64" ]; then cargo build --release --features bundled,windows-installer --target x86_64-pc-windows-gnu; fi
ENV BINDGEN_EXTRA_CLANG_ARGS=
RUN if [ $target = "win64" ]; then cp Microsoft.Web.WebView2.*/build/native/x64/WebView2Loader.dll target/x86_64-pc-windows-gnu/release; fi
RUN if [ $target = "win64" ]; then makensis package/windows.nsi; fi
RUN if [ $target = "win64" ]; then cp package/stonenet-installer.exe ../out; fi
ENV PKG_CONFIG_ALLOW_CROSS=true
ENV PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
RUN if [ $target = "arm64" ]; then cargo deb -p stonenet-desktop --target aarch64-unknown-linux-gnu; fi
RUN if [ $target = "arm64" ]; then cargo deb --features apt,unbundled --target aarch64-unknown-linux-gnu; fi
RUN if [ $target = "arm64" ]; then cp target/aarch64-unknown-linux-gnu/debian/* ../out; fi
ENV PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
RUN if [ $target = "amd64" ]; then cargo deb -p stonenet-desktop --target x86_64-unknown-linux-gnu; fi
RUN if [ $target = "amd64" ]; then cargo deb --features apt,unbundled --target x86_64-unknown-linux-gnu; fi
RUN if [ $target = "amd64" ]; then cp target/x86_64-unknown-linux-gnu/debian/* ../out; fi
ENV PKG_CONFIG_PATH=/usr/lib/arm-linux-gnueabihf/pkgconfig
ENV CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
RUN if [ $target = "armhf" ]; then cargo deb -p stonenet-desktop --target armv7-unknown-linux-gnueabihf; fi
RUN if [ $target = "armhf" ]; then cargo deb --features apt,unbundled --target armv7-unknown-linux-gnueabihf; fi
RUN if [ $target = "armhf" ]; then cp target/armv7-unknown-linux-gnueabihf/debian/* ../out; fi

