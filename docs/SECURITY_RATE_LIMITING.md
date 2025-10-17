# Security Rate Limiting

## Overview

The agent implements rate limiting and lockout protection to prevent brute-force attacks on TOTP and password authentication.

## How It Works

### Exponential Backoff

After each failed authentication attempt, the agent enforces increasingly long delays:

- Attempt 1: No delay
- Attempt 2: 30 seconds
- Attempt 3: 60 seconds
- Attempt 4: 120 seconds
- Attempt 5: 240 seconds
- Attempt 6+: Lockout

### Lockout Modes

#### Temporary Lockout (default)
- Agent locks for 15 minutes (configurable)
- Automatically recovers after duration
- Lockout state persists across restarts

#### Permanent Lockout
- Agent locks indefinitely
- Requires manual intervention to clear
- Use: `gentility security clear-lockout`

## Configuration

```yaml
security:
  mode: totp
  totp_secret: YOUR_SECRET

  rate_limiting:
    enabled: true            # Enable/disable rate limiting
    max_attempts: 5          # Failed attempts before lockout
    lockout_mode: temporary  # "temporary" or "permanent"
    lockout_duration: 900    # Seconds (15 minutes)
```

## Server Integration

When an agent enters lockout, it sends a `security_lockout` message:

```json
{
  "type": "security_lockout",
  "lockout_mode": "temporary",
  "lockout_until": 1234567890.0,
  "failed_attempts": 5,
  "timestamp": 1234567890.0
}
```

Servers should:
1. Display warning in UI
2. Show remaining lockout time
3. Stop sending unlock attempts
4. Monitor status updates for recovery

## CLI Commands

```bash
# Clear lockout state
gentility security clear-lockout

# Check if agent is locked
gentility status
```

## Error Responses

### During Backoff
```json
{
  "error": "Too many failed attempts",
  "retry_after": 120,
  "attempts_remaining": 2
}
```

### Temporary Lockout
```json
{
  "error": "Agent locked due to too many failed attempts",
  "lockout_mode": "temporary",
  "locked_until": 1234567890.0,
  "locked_for": 900
}
```

### Permanent Lockout
```json
{
  "error": "Agent permanently locked due to too many failed attempts",
  "lockout_mode": "permanent",
  "message": "Manual intervention required"
}
```

## Security Considerations

- Lockout state persists in config file (survives restarts)
- Backoff timing is in-memory (resets on restart)
- Successful unlock clears all rate limiting state
- Rate limiting applies to both password and TOTP modes
