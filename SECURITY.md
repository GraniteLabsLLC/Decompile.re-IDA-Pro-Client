# Security Policy

## Reporting A Vulnerability

Report security issues through
[GitHub private vulnerability reporting](https://github.com/GraniteLabsLLC/Decompile.re-IDA-Pro-Client/security/advisories/new).
Do not include credentials, private binaries, or customer data in a public
issue.

Include the affected plugin version, IDA version, operating system, concise
reproduction steps, and impact. Reports will be acknowledged after triage.

## Credential Handling

The client stores refresh credentials and device private keys only through a
native operating system credential backend supported by `keyring`. It refuses
insecure plaintext and fallback keyring backends. Short-lived access tokens are
held only in process memory.

The client permits credential-bearing HTTP only for a loopback development
server. Production API communication requires HTTPS and redirects are disabled.

## Client Updates

The updater never receives GitHub credentials. It reads only the configured
public repository, follows redirects only across an explicit GitHub download
host allowlist, bounds metadata and archive sizes, and verifies the existing
ECDSA P-256 release-manifest signature before trusting release metadata.

Plugin archives are checked against the signed size and SHA-256 digest before
extraction. Encrypted entries, links, special files, path traversal, excessive
file counts, and excessive expanded sizes are rejected. Activation uses
same-volume staging and retains a rollback copy. Dependency changes require
the setup wizard rather than running package installation from inside IDA.

## Generated Projects

The reconstruction engine can create files only under a directory selected by
the user. Path traversal and symlink escapes are rejected. CMake configuration
can execute local commands, so every changed CMake configuration requires
explicit approval before configure or build is started.
