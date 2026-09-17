# rAthena Argon2id password compatibility

FluxCP can use the `passwd_type` schema and password formats provided by the matching rAthena authentication branch.

Configure each `LoginServer` entry in `config/servers.php`:

```php
'UseMD5' => false,
'UseArgon2id' => true,
'PasswordHashPepper' => 'the same secret as rAthena password_hash_pepper',
'PasswordWirePepper' => '', // or the same value as rAthena password_pepper
'UsePasswordEnrollment' => true,
```

## Rules

- `PasswordHashPepper` is secret. Inject it at runtime; do not commit it.
- `PasswordWirePepper` must exactly match rAthena and may contain at most 20 bytes. It is not secret: the login protocol gives it to clients. Enabling it requires every game client to use `<passwordencrypt>` and makes captured login digests replayable. Use a VPN for actual transport security.
- Changing either pepper can lock out existing accounts. Hash-pepper rotation requires a staged verifier that retains the prior key; wire-pepper rotation requires password resets.
- `UsePasswordEnrollment` enables the administrator-only **Password Recovery** action on an account page. Activation marks the account so its next **game** login stores the supplied password. FluxCP refuses web login while this flag is active. Activate it only when the owner is ready because anyone who knows the account name can choose the password until enrollment completes.

With Argon2id enabled, registration, web login, password changes, and email-token password recovery all use the same preprocessing and Argon2 parameters as rAthena. A successful web login migrates legacy plaintext/MD5 rows and outdated storage modes. FluxCP password audit columns store `[redacted]`, not cleartext passwords or reusable hashes.

PHP must expose `PASSWORD_ARGON2ID`, and the rAthena `login.user_pass` and `passwd_type` schema upgrade must already be installed.

## Email recovery

Registration confirmation lasts 24 hours. Password and PIN recovery links last 30 minutes. Tokens contain 256 bits of randomness, are stored only as SHA-256 hashes, and are single-use. Password reset stores a new Argon2id credential; PIN reset clears the PIN so the game client requires a replacement.

Production sends through authenticated STARTTLS SMTP. The SMTP password must be injected at runtime and must not be committed or included in a Nix store path. Recovery request pages return the same response whether account details match, and repeated requests are rate-limited by account and IP.
