class Stonenet < Formula
  homepage "https://stonenet.org/"
  url "https://github.com/bamidev/stonenet/archive/refs/tags/v0.0.17.tar.gz"
  sha256 "06cecc3336902ee1560af2455f65fc10833b1e0ac7e0ec03283ebf7347b7625d"

  depends_on "rust"

  service do
    run opt_bin/"stonenetd"
    launch_only_once true
    keep_alive true
  end

  def install
    args = %W[
      PREFIX=#{prefix}
    ]
    system "cargo", "build", "--release"
    system "cargo", "build", "-p", "stonenet-desktop", "--release"
    
    bin.install "target/release/stonenetd" => "stonenetd"
    bin.install "target/release/stonenet-desktop" => "stonenet-desktop"
    system "install" "conf/base.toml" "#{prefix}/usr/local/etc/config.toml"
    system "install" "static" "#{prefix}/usr/local/share/stonenet/static"
    system "install" "templates" "#{prefix}/usr/local/share/stonenet/templates"
  end
end

