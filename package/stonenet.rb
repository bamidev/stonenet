class Stonenet < Formula
  homepage "https://stonenet.org/"
  url "https://github.com/bamidev/stonenet/archive/refs/tags/{{VERSION}}.tar.gz"
  sha256 "{{HASH}}"

  depends_on "rust"

  def install
    args = %W[
      PREFIX=#{prefix}
    ]
    system "./install.sh", *args
  end
end

