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

  def self.restore_lockout(lockout_until : Time?)
    @@locked_out = true
    @@lockout_until = lockout_until
  end

  def self.persist_lockout
    # Returns hash to be saved to config
    {
      "locked_out" => @@locked_out,
      "lockout_until" => @@lockout_until ? @@lockout_until.not_nil!.to_unix_f : nil,
    }
  end

  def self.mode
    @@mode
  end

  def self.can_attempt? : Bool
    return true unless @@rate_limiting_enabled
    return false if @@locked_out

    return true unless @@next_attempt_allowed
    Time.utc >= @@next_attempt_allowed.not_nil!
  end

  def self.time_until_next_attempt : Int32
    return 0 unless @@next_attempt_allowed
    remaining = (@@next_attempt_allowed.not_nil! - Time.utc).total_seconds.ceil.to_i
    [remaining, 0].max
  end

  def self.locked_out? : Bool
    @@locked_out
  end

  def self.failed_attempt_count : Int32
    @@failed_attempts
  end

  def self.lockout_until : Time?
    @@lockout_until
  end

  def self.max_attempts : Int32
    @@max_attempts
  end

  def self.unlock_timeout : Int32
    @@unlock_timeout
  end

  def self.extendable? : Bool
    @@extendable
  end

  def self.lockout_mode : String
    @@lockout_mode
  end

  def self.was_locked_out? : Bool
    # Track if we just cleared a lockout (for cleanup)
    # Implementation: check if lockout was just cleared
    false # TODO: implement tracking if needed
  end

  private def self.calculate_backoff_seconds(attempt : Int32) : Int32
    # 30s, 60s, 120s, 240s (or 1s, 2s, 4s, 8s in test mode)
    base = ENV.fetch("RATE_LIMIT_TEST_MODE", "false") == "true" ? 1 : 30
    (base * (2 ** (attempt - 1))).to_i
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

    # Check if locked out
    if @@locked_out
      now = Time.utc
      if @@lockout_until && now >= @@lockout_until.not_nil!
        # Temporary lockout expired
        clear_lockout
      else
        # Still locked (temporary or permanent)
        return false
      end
    end

    # Check if backoff in effect
    if @@rate_limiting_enabled && @@next_attempt_allowed
      return false if Time.utc < @@next_attempt_allowed.not_nil!
    end

    # Validate credentials
    success = validate_credential(password_or_totp)

    if success
      reset_rate_limiting
      @@active = true
      @@unlock_time = Time.utc
      @@initial_unlock_time ||= Time.utc
      true
    else
      handle_failed_attempt if @@rate_limiting_enabled
      false
    end
  end

  private def self.validate_credential(password_or_totp : String) : Bool
    case @@mode
    when "password"
      !!(@@password && password_or_totp == @@password)
    when "totp"
      validate_totp(password_or_totp)
    else
      false
    end
  end

  private def self.handle_failed_attempt
    @@failed_attempts += 1
    @@last_attempt_time = Time.utc

    if @@failed_attempts >= @@max_attempts
      # Trigger lockout
      @@locked_out = true
      if @@lockout_mode == "temporary"
        @@lockout_until = Time.utc + @@lockout_duration.seconds
      else
        @@lockout_until = nil # Permanent
      end
    else
      # Set backoff
      backoff = calculate_backoff_seconds(@@failed_attempts)
      @@next_attempt_allowed = Time.utc + backoff.seconds
    end
  end

  private def self.reset_rate_limiting
    @@failed_attempts = 0
    @@last_attempt_time = nil
    @@next_attempt_allowed = nil
  end

  def self.clear_lockout
    @@locked_out = false
    @@lockout_until = nil
    reset_rate_limiting
  end

  def self.extend_unlock
    return unless @@active && @@extendable
    @@unlock_time = Time.utc
  end

  def self.lock
    @@active = false
    @@unlock_time = nil
    @@initial_unlock_time = nil
    # Reset rate limiting state when locking
    clear_lockout
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
    status_hash = {
      "security_enabled" => @@mode != "none",
      "security_mode"    => @@mode,
      "active"           => unlocked?,
      "time_remaining"   => time_remaining,
      "extendable"       => @@extendable,
    }

    # Add lockout info if applicable
    if @@locked_out
      status_hash = status_hash.merge({
        "locked_out"   => true,
        "lockout_mode" => @@lockout_mode,
      })

      if @@lockout_until
        status_hash = status_hash.merge({
          "lockout_until" => @@lockout_until.not_nil!.to_unix_f
        })
      end
    end

    status_hash
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
