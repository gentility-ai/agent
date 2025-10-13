class GentilityAgent < Formula
  desc "Daemon for Gentility AI remote access"
  homepage "https://gentility.ai"
  url "https://github.com/gentility-ai/agent.git",
      tag: "v1.1.6"
  license "MIT"

  depends_on "crystal" => :build
  depends_on "openssl@3"
  depends_on "bdw-gc"
  depends_on "libevent"
  depends_on "pcre2"

  def install
    # Install Crystal dependencies
    system "shards", "install", "--production"

    # Set up OpenSSL paths for macOS
    ENV["PKG_CONFIG_PATH"] = "#{Formula["openssl@3"].opt_lib}/pkgconfig"

    # Build the binary with proper linking
    system "crystal", "build", "src/agent.cr",
           "--release", "--no-debug", "-o", "gentility",
           "--link-flags", "-L#{Formula["openssl@3"].opt_lib}"

    # Install the binary
    bin.install "gentility"

    # Install configuration example
    etc.install "gentility.yaml.example"
  end

  def caveats
    <<~EOS
      Quick Setup:
        gentility auth

      This will log you in and associate this machine with your account.

      Then start as a service:
        brew services start gentility-agent

      Or run manually:
        gentility run

      For help: gentility help
    EOS
  end

  service do
    run [opt_bin/"gentility", "run"]
    environment_variables GENTILITY_CONFIG: etc/"gentility.yaml"
    run_type :immediate
    keep_alive true
    log_path var/"log/gentility-agent/stdout.log"
    error_log_path var/"log/gentility-agent/stderr.log"
  end

  test do
    # Test that the binary was installed and shows help
    assert_match "Gentility", shell_output("#{bin}/gentility help")
  end
end
