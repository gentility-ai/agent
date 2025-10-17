require "crotp"

# Global security state management
module Security
  @@mode : String = "none"
  @@password : String? = nil
  @@totp_secret : String? = nil
  @@unlock_timeout : Int32 = 1800
  @@extendable : Bool = true
  @@active : Bool = false
  @@unlock_time : Time? = nil
  @@initial_unlock_time : Time? = nil
  @@promiscuous_enabled : Bool = true
  @@promiscuous_auth_mode : String = "password"

  # Rate limiting state (in-memory)
  @@failed_attempts : Int32 = 0
  @@last_attempt_time : Time? = nil
  @@next_attempt_allowed : Time? = nil

  # Lockout state (persisted)
  @@locked_out : Bool = false
  @@lockout_until : Time? = nil

  # Rate limiting config
  @@rate_limiting_enabled : Bool = true
  @@max_attempts : Int32 = 5
  @@lockout_mode : String = "temporary"
  @@lockout_duration : Int32 = 900

  def self.configure(mode : String, password : String?, totp_secret : String?, timeout : Int32, extendable : Bool, promiscuous_enabled : Bool = true, promiscuous_auth_mode : String = "password", rate_limiting_enabled : Bool = true, max_attempts : Int32 = 5, lockout_mode : String = "temporary", lockout_duration : Int32 = 900)
    @@mode = mode
    @@password = password
    @@totp_secret = totp_secret
    @@unlock_timeout = timeout
    @@extendable = extendable
    @@promiscuous_enabled = promiscuous_enabled
    @@promiscuous_auth_mode = promiscuous_auth_mode
    @@rate_limiting_enabled = rate_limiting_enabled
    @@max_attempts = max_attempts
    @@lockout_mode = lockout_mode
    @@lockout_duration = lockout_duration
  end

  def self.mode
    @@mode
  end

  def self.unlocked?
    return true if @@mode == "none"

    return false unless @@active

    now = Time.utc
    return false unless @@unlock_time && @@initial_unlock_time

    # Check if we've exceeded the hard timeout from initial unlock
    if now - @@initial_unlock_time.not_nil! > @@unlock_timeout.seconds
      lock
      return false
    end

    # If extendable, also check the rolling timeout
    if @@extendable && now - @@unlock_time.not_nil! > @@unlock_timeout.seconds
      lock
      return false
    end

    true
  end

  def self.unlock(password_or_totp : String) : Bool
    return true if @@mode == "none"

    success = case @@mode
              when "password"
                @@password && password_or_totp == @@password
              when "totp"
                validate_totp(password_or_totp)
              else
                false
              end

    if success
      now = Time.utc
      @@active = true
      @@unlock_time = now
      @@initial_unlock_time = now unless @@initial_unlock_time
    end

    !!success
  end

  def self.extend_unlock
    return unless @@active && @@extendable
    @@unlock_time = Time.utc
  end

  def self.lock
    @@active = false
    @@unlock_time = nil
    @@initial_unlock_time = nil
  end

  def self.time_remaining : Int32
    return -1 if @@mode == "none" || !@@active
    return 0 unless @@unlock_time && @@initial_unlock_time

    now = Time.utc
    initial_elapsed = (now - @@initial_unlock_time.not_nil!).total_seconds.to_i
    hard_remaining = @@unlock_timeout - initial_elapsed

    if @@extendable
      rolling_elapsed = (now - @@unlock_time.not_nil!).total_seconds.to_i
      rolling_remaining = @@unlock_timeout - rolling_elapsed
      [hard_remaining, rolling_remaining].min
    else
      hard_remaining
    end
  end

  def self.status
    {
      "security_enabled" => @@mode != "none",
      "security_mode"    => @@mode,
      "active"           => unlocked?,
      "time_remaining"   => time_remaining,
      "extendable"       => @@extendable,
    }
  end

  def self.validate_promiscuous_auth(credential : String) : Bool
    return false unless @@promiscuous_enabled

    success = case @@promiscuous_auth_mode
              when "password"
                @@password && credential == @@password
              when "totp"
                validate_totp(credential)
              else
                false
              end

    !!success
  end

  def self.promiscuous_enabled?
    @@promiscuous_enabled
  end

  def self.export_config
    {
      "success"         => true,
      "security_config" => {
        "mode"                  => @@mode,
        "password"              => @@password,
        "totp_secret"           => @@totp_secret,
        "timeout"               => @@unlock_timeout,
        "extendable"            => @@extendable,
        "promiscuous_enabled"   => @@promiscuous_enabled,
        "promiscuous_auth_mode" => @@promiscuous_auth_mode,
      },
    }
  end

  private def self.validate_totp(code : String) : Bool
    return false unless @@totp_secret

    begin
      totp = CrOTP::TOTP.new(@@totp_secret.not_nil!)
      totp.verify(code)
    rescue
      false
    end
  end
end
