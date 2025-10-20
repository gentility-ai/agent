require "http/client"
require "http/server"
require "json"
require "uri"
require "base64"
require "openssl"
require "digest/sha256"

module OAuth
  # OAuth2 configuration for different environments
  class Config
    CLIENT_ID = "gentility-agent"
    SCOPES    = "agent:connect agent:execute"

    getter authorization_endpoint : String
    getter token_endpoint : String
    getter device_code_endpoint : String
    getter client_id : String
    getter scopes : String

    def initialize(environment : String = "prod")
      @authorization_endpoint = AgentConfig::ServerURLs.oauth_authorize_url(environment)
      @token_endpoint = AgentConfig::ServerURLs.oauth_token_url(environment)
      @device_code_endpoint = AgentConfig::ServerURLs.oauth_device_code_url(environment)
      @client_id = CLIENT_ID
      @scopes = SCOPES
    end
  end

  # OAuth token response
  struct TokenResponse
    include JSON::Serializable

    property access_token : String
    property refresh_token : String?
    property expires_in : Int32?
    property token_type : String
  end

  # Device code response
  struct DeviceCodeResponse
    include JSON::Serializable

    property device_code : String
    property user_code : String
    property verification_uri : String
    property verification_uri_complete : String?
    property expires_in : Int32
    property interval : Int32?
  end

  # PKCE (Proof Key for Code Exchange) generator
  class PKCE
    getter verifier : String
    getter challenge : String

    def initialize
      # Generate random 43-128 character verifier
      @verifier = generate_verifier
      @challenge = generate_challenge(@verifier)
    end

    private def generate_verifier : String
      # Generate 32 random bytes (will be 43 chars in base64url)
      random_bytes = Random::Secure.random_bytes(32)
      Base64.urlsafe_encode(random_bytes, padding: false)
    end

    private def generate_challenge(verifier : String) : String
      # SHA256 hash of verifier, then base64url encode
      digest = Digest::SHA256.digest(verifier)
      Base64.urlsafe_encode(digest, padding: false)
    end
  end

  # OAuth2 authentication flow orchestrator
  class Authenticator
    @config : Config
    @pkce : PKCE
    @debug : Bool

    def initialize(environment : String = "prod", @debug : Bool = false)
      @config = Config.new(environment)
      @pkce = PKCE.new
    end

    private def debug_log(message : String)
      if @debug
        puts "[DEBUG] #{Time.local.to_s("%Y-%m-%d %H:%M:%S")} #{message}"
      end
    end

    # Build authorization URL
    def build_authorize_url(callback_port : Int32) : String
      redirect_uri = "http://localhost:#{callback_port}/callback"

      params = URI::Params.build do |form|
        form.add "client_id", @config.client_id
        form.add "redirect_uri", redirect_uri
        form.add "response_type", "code"
        form.add "scope", @config.scopes
        form.add "code_challenge", @pkce.challenge
        form.add "code_challenge_method", "S256"
        form.add "state", generate_state
      end

      "#{@config.authorization_endpoint}?#{params}"
    end

    # Exchange authorization code for tokens
    def exchange_code(code : String, callback_port : Int32) : TokenResponse
      redirect_uri = "http://localhost:#{callback_port}/callback"

      client = HTTP::Client.new(URI.parse(@config.token_endpoint))

      body = URI::Params.build do |form|
        form.add "grant_type", "authorization_code"
        form.add "code", code
        form.add "redirect_uri", redirect_uri
        form.add "client_id", @config.client_id
        form.add "code_verifier", @pkce.verifier
      end

      headers = HTTP::Headers{
        "Content-Type" => "application/x-www-form-urlencoded",
      }

      debug_log("POST #{@config.token_endpoint}")
      debug_log("Request body: grant_type=authorization_code&code=#{code[0...10]}...&client_id=#{@config.client_id}")

      response = client.post(@config.token_endpoint, headers: headers, body: body)

      debug_log("Response status: #{response.status_code}")
      debug_log("Response body: #{response.body[0...100]}...")

      if response.status_code == 200
        TokenResponse.from_json(response.body)
      else
        raise "Token exchange failed: HTTP #{response.status_code} - #{response.body}"
      end
    end

    # Refresh access token using refresh token
    def refresh_token(refresh_token : String) : TokenResponse
      client = HTTP::Client.new(URI.parse(@config.token_endpoint))

      body = URI::Params.build do |form|
        form.add "grant_type", "refresh_token"
        form.add "refresh_token", refresh_token
        form.add "client_id", @config.client_id
      end

      headers = HTTP::Headers{
        "Content-Type" => "application/x-www-form-urlencoded",
      }

      response = client.post(@config.token_endpoint, headers: headers, body: body)

      if response.status_code == 200
        TokenResponse.from_json(response.body)
      else
        raise "Token refresh failed: HTTP #{response.status_code} - #{response.body}"
      end
    end

    # Request device code for device flow (RFC 8628)
    def request_device_code : DeviceCodeResponse
      client = HTTP::Client.new(URI.parse(@config.device_code_endpoint))

      body = URI::Params.build do |form|
        form.add "client_id", @config.client_id
        form.add "scope", @config.scopes
      end

      headers = HTTP::Headers{
        "Content-Type" => "application/x-www-form-urlencoded",
      }

      debug_log("POST #{@config.device_code_endpoint}")
      debug_log("Request body: client_id=#{@config.client_id}&scope=#{@config.scopes}")

      response = client.post(@config.device_code_endpoint, headers: headers, body: body)

      debug_log("Response status: #{response.status_code}")
      debug_log("Response body: #{response.body}")

      if response.status_code == 200
        DeviceCodeResponse.from_json(response.body)
      else
        raise "Device code request failed: HTTP #{response.status_code} - #{response.body}"
      end
    end

    # Poll for token using device code
    def poll_for_token(device_code : String, interval : Int32 = 5) : TokenResponse
      client = HTTP::Client.new(URI.parse(@config.token_endpoint))

      body = URI::Params.build do |form|
        form.add "grant_type", "urn:ietf:params:oauth:grant-type:device_code"
        form.add "device_code", device_code
        form.add "client_id", @config.client_id
      end

      headers = HTTP::Headers{
        "Content-Type" => "application/x-www-form-urlencoded",
      }

      poll_count = 0
      loop do
        poll_count += 1
        debug_log("Polling for token (attempt ##{poll_count})...")
        debug_log("POST #{@config.token_endpoint}")

        response = client.post(@config.token_endpoint, headers: headers, body: body)

        debug_log("Response status: #{response.status_code}")
        debug_log("Response body: #{response.body[0...150]}...")

        case response.status_code
        when 200
          # Success!
          debug_log("Token received successfully!")
          return TokenResponse.from_json(response.body)
        when 400
          # Check error type
          error_data = JSON.parse(response.body)
          error = error_data["error"]?.try(&.as_s)

          case error
          when "authorization_pending"
            # User hasn't authorized yet, keep polling
            debug_log("Authorization pending, waiting #{interval} seconds before next poll...")
            sleep interval.seconds
          when "slow_down"
            # Server wants us to slow down
            debug_log("Server requested slow_down, waiting #{interval + 5} seconds...")
            sleep (interval + 5).seconds
          when "expired_token"
            raise "Device code expired. Please try again."
          when "access_denied"
            raise "User denied authorization."
          else
            raise "Token request failed: #{error} - #{error_data["error_description"]?}"
          end
        else
          raise "Token request failed: HTTP #{response.status_code} - #{response.body}"
        end
      end
    end

    private def generate_state : String
      # Generate random state for CSRF protection
      random_bytes = Random::Secure.random_bytes(16)
      Base64.urlsafe_encode(random_bytes, padding: false)
    end
  end

  # Callback server to capture OAuth redirect
  class CallbackServer
    @server : HTTP::Server
    @port : Int32
    @code : String?
    @error : String?
    @done : Channel(Bool)

    def initialize
      @done = Channel(Bool).new
      @port = 0

      @server = HTTP::Server.new do |context|
        handle_request(context)
      end
    end

    def start : Int32
      # Bind to random available port
      address = @server.bind_unused_port
      @port = address.port

      # Start server in background
      spawn do
        @server.listen
      end

      @port
    end

    def wait_for_callback(timeout : Time::Span = 120.seconds) : String
      select
      when @done.receive
        if error = @error
          raise "OAuth error: #{error}"
        elsif code = @code
          return code
        else
          raise "No authorization code received"
        end
      when timeout(timeout)
        stop
        raise "Timeout waiting for OAuth callback"
      end
    end

    def stop
      @server.close
    end

    private def handle_request(context : HTTP::Server::Context)
      if context.request.path == "/callback"
        query = context.request.query_params

        if error = query["error"]?
          @error = "#{error}: #{query["error_description"]?}"
          show_error_page(context, @error.not_nil!)
          @done.send(true)
        elsif code = query["code"]?
          @code = code
          show_success_page(context)
          @done.send(true)
        else
          show_error_page(context, "No code or error in callback")
          @done.send(true)
        end
      else
        context.response.status = HTTP::Status::NOT_FOUND
        context.response.print "Not found"
      end
    end

    private def show_success_page(context : HTTP::Server::Context)
      context.response.content_type = "text/html"
      context.response.print <<-HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>Authentication Successful</title>
          <style>
            body {
              font-family: system-ui, -apple-system, sans-serif;
              display: flex;
              align-items: center;
              justify-content: center;
              min-height: 100vh;
              margin: 0;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
              background: white;
              padding: 3rem;
              border-radius: 1rem;
              box-shadow: 0 20px 60px rgba(0,0,0,0.3);
              text-align: center;
              max-width: 500px;
            }
            h1 { color: #2d3748; margin: 0 0 1rem 0; }
            p { color: #4a5568; line-height: 1.6; }
            .checkmark {
              width: 80px;
              height: 80px;
              border-radius: 50%;
              display: block;
              stroke-width: 3;
              stroke: #4ade80;
              stroke-miterlimit: 10;
              margin: 0 auto 2rem auto;
              box-shadow: inset 0px 0px 0px #4ade80;
              animation: fill .4s ease-in-out .4s forwards, scale .3s ease-in-out .9s both;
            }
            .checkmark__circle {
              stroke-dasharray: 166;
              stroke-dashoffset: 166;
              stroke-width: 2;
              stroke-miterlimit: 10;
              stroke: #4ade80;
              fill: none;
              animation: stroke 0.6s cubic-bezier(0.65, 0, 0.45, 1) forwards;
            }
            .checkmark__check {
              transform-origin: 50% 50%;
              stroke-dasharray: 48;
              stroke-dashoffset: 48;
              animation: stroke 0.3s cubic-bezier(0.65, 0, 0.45, 1) 0.8s forwards;
            }
            @keyframes stroke {
              100% { stroke-dashoffset: 0; }
            }
            @keyframes scale {
              0%, 100% { transform: none; }
              50% { transform: scale3d(1.1, 1.1, 1); }
            }
            @keyframes fill {
              100% { box-shadow: inset 0px 0px 0px 30px #4ade80; }
            }
          </style>
        </head>
        <body>
          <div class="container">
            <svg class="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
              <circle class="checkmark__circle" cx="26" cy="26" r="25" fill="none"/>
              <path class="checkmark__check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8"/>
            </svg>
            <h1>Authentication Successful!</h1>
            <p>Your Gentility agent has been authenticated. You can close this window and return to the terminal.</p>
          </div>
        </body>
        </html>
      HTML
    end

    private def show_error_page(context : HTTP::Server::Context, error : String)
      context.response.content_type = "text/html"
      context.response.print <<-HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>Authentication Error</title>
          <style>
            body {
              font-family: system-ui, -apple-system, sans-serif;
              display: flex;
              align-items: center;
              justify-content: center;
              min-height: 100vh;
              margin: 0;
              background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            }
            .container {
              background: white;
              padding: 3rem;
              border-radius: 1rem;
              box-shadow: 0 20px 60px rgba(0,0,0,0.3);
              text-align: center;
              max-width: 500px;
            }
            h1 { color: #2d3748; margin: 0 0 1rem 0; }
            p { color: #4a5568; line-height: 1.6; }
            .error { color: #e53e3e; font-family: monospace; background: #fff5f5; padding: 1rem; border-radius: 0.5rem; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Authentication Error</h1>
            <p class="error">#{error}</p>
            <p>Please try again or contact support if the problem persists.</p>
          </div>
        </body>
        </html>
      HTML
    end
  end

  # Main OAuth flow coordinator
  class Flow
    def self.authenticate(environment : String = "prod", headless : Bool = false, debug : Bool = false) : TokenResponse
      auth = Authenticator.new(environment, debug)
      callback_server = CallbackServer.new

      # Start callback server
      port = callback_server.start
      puts "📡 Started callback server on http://localhost:#{port}"
      puts "[DEBUG] Callback server listening on port #{port}" if debug

      # Build authorization URL
      auth_url = auth.build_authorize_url(port)
      puts "[DEBUG] Authorization URL: #{auth_url}" if debug

      if headless
        # Headless mode: display URL for manual opening
        puts ""
        puts "🔐 OAuth Authentication Required"
        puts "================================"
        puts ""
        puts "Please open this URL in your browser:"
        puts ""
        puts "  #{auth_url}"
        puts ""
        puts "Waiting for authentication..."
      else
        # Try to open browser automatically
        puts ""
        puts "🔐 Opening browser for authentication..."
        puts ""

        opened = open_browser(auth_url)

        unless opened
          puts "Could not open browser automatically."
          puts "Please open this URL manually:"
          puts ""
          puts "  #{auth_url}"
          puts ""
        end

        puts "Waiting for authentication..."
      end

      # Wait for callback
      begin
        code = callback_server.wait_for_callback
        puts "✅ Authorization code received"
        puts "[DEBUG] Authorization code: #{code[0...10]}..." if debug

        # Exchange code for tokens
        puts "🔄 Exchanging code for access token..."
        tokens = auth.exchange_code(code, port)

        puts "✅ Authentication successful!"
        puts "[DEBUG] Access token received: #{tokens.access_token[0...20]}..." if debug
        tokens
      ensure
        callback_server.stop
      end
    end

    # Device Code Flow - for SSH/remote scenarios
    def self.authenticate_device(environment : String = "prod", debug : Bool = false) : TokenResponse
      auth = Authenticator.new(environment, debug)

      # Step 1: Request device code
      puts "🔐 Starting device authentication..."
      puts ""

      device_response = auth.request_device_code
      puts "[DEBUG] Device code: #{device_response.device_code[0...20]}..." if debug
      puts "[DEBUG] User code: #{device_response.user_code}" if debug

      # Step 2: Display instructions to user
      puts "📱 Please authorize this device:"
      puts ""
      puts "  1. Visit: #{device_response.verification_uri}"
      puts "  2. Enter code: #{device_response.user_code}"
      puts ""

      # If server provided a complete URI, show it too
      if complete_uri = device_response.verification_uri_complete
        puts "Or visit this URL directly:"
        puts "  #{complete_uri}"
        puts ""
      end

      puts "⏳ Waiting for authorization (expires in #{device_response.expires_in} seconds)..."
      puts ""

      # Step 3: Poll for token
      interval = device_response.interval || 5
      puts "[DEBUG] Polling interval: #{interval} seconds" if debug
      tokens = auth.poll_for_token(device_response.device_code, interval)

      puts "✅ Authentication successful!"
      puts "[DEBUG] Access token received: #{tokens.access_token[0...20]}..." if debug
      tokens
    end

    private def self.open_browser(url : String) : Bool
      {% if flag?(:darwin) %}
        # macOS
        result = Process.run("open", [url], error: Process::Redirect::Close)
        result.success?
      {% elsif flag?(:linux) %}
        # Linux - try xdg-open
        result = Process.run("xdg-open", [url], error: Process::Redirect::Close)
        result.success?
      {% elsif flag?(:win32) %}
        # Windows
        result = Process.run("cmd", ["/c", "start", url], error: Process::Redirect::Close)
        result.success?
      {% else %}
        false
      {% end %}
    rescue
      false
    end
  end
end
