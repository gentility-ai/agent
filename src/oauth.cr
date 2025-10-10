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
    PRODUCTION_AUTHORIZE_URL = "https://core.gentility.ai/oauth/authorize"
    PRODUCTION_TOKEN_URL     = "https://core.gentility.ai/oauth/token"
    DEVELOPMENT_AUTHORIZE_URL = "https://termite-lasting-lively.ngrok-free.app/oauth/authorize"
    DEVELOPMENT_TOKEN_URL     = "https://termite-lasting-lively.ngrok-free.app/oauth/token"
    CLIENT_ID                = "gentility-agent"
    SCOPES                   = "agent:connect agent:execute"

    getter authorization_endpoint : String
    getter token_endpoint : String
    getter client_id : String
    getter scopes : String

    def initialize(environment : String = "prod")
      @authorization_endpoint, @token_endpoint = case environment
                                                 when "dev", "development"
                                                   {DEVELOPMENT_AUTHORIZE_URL, DEVELOPMENT_TOKEN_URL}
                                                 else
                                                   {PRODUCTION_AUTHORIZE_URL, PRODUCTION_TOKEN_URL}
                                                 end
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

    def initialize(environment : String = "prod")
      @config = Config.new(environment)
      @pkce = PKCE.new
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

      response = client.post(@config.token_endpoint, headers: headers, body: body)

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
    def self.authenticate(environment : String = "prod", headless : Bool = false) : TokenResponse
      auth = Authenticator.new(environment)
      callback_server = CallbackServer.new

      # Start callback server
      port = callback_server.start
      puts "📡 Started callback server on http://localhost:#{port}"

      # Build authorization URL
      auth_url = auth.build_authorize_url(port)

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

        # Exchange code for tokens
        puts "🔄 Exchanging code for access token..."
        tokens = auth.exchange_code(code, port)

        puts "✅ Authentication successful!"
        tokens
      ensure
        callback_server.stop
      end
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
