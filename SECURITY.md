# Security

## Vulnerabilities

### 1 - 2021/05/06 - rules can generate fact with authority or ambient tags using variables

Affected versions:
- Rust <1.1.0
- Java: <1.1.0
- Go: <1.0.0

#### Description

Rules of the format `operation($ambient, #read) <- operation($ambient, $any)`
provided by blocks other than the authority block could be used to generate
facts with the `#authority` or `#ambient` tags.
This can result in elevation of privilege.

#### Recommandations

Upgrade immediately to non affected versions

#### Credits

This issue was reported by @svvac. Thanks a lot!

### 0 - 2021/05/06 - unbound variables in rule head

Affected versions:
- Rust <1.0.1
- Java: results in Null Pointer Exception in versions <1.1.0
- Go: not affected

#### Description

Rules of the format `operation($unbound, #read) <- operation($any1, $any2)` could generate invalid facts containing variables, that would then confuse matching of other checks and make them succeed.
This can result in elevation of privilege.

#### Recommandations

Upgrade immediately to non affected versions

#### Credits

This issue was reported by @svvac. Thanks a lot!
