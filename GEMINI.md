# CodeLock Project Rules & Architectural Guidelines

## 1. Project Architecture
- **Multi-Repository Architecture:**
  - `codelock-laravel`: Reusable Composer package (client-side enforcement middleware & verification library).
  - `codelock-server`: Standalone private Laravel 12 application (central licensing authority, key management, administration).
- **Asymmetric Key Separation:**
  - The client package (`codelock-laravel`) must **NEVER** contain or access server private signing keys.
  - The client package only receives and embeds/configures public verification keys.
- **Cryptographic Standards:**
  - All licenses and remote status envelopes use **Ed25519** digital signatures with deterministic RFC 8785 canonical JSON sorting.
  - Use native **PHP sodium** (`sodium_crypto_sign_verify_detached`, `sodium_crypto_sign_detached`). Do not invoke external CLI binaries or `exec()` for cryptography.
- **Protocol Compatibility:**
  - Keep client package and server API contracts strictly compatible. Never introduce breaking changes to JSON payloads or API endpoints without explicit deprecation and cross-system migration plans.

## 2. Laravel & Codebase Standards
- Follow standard Laravel conventions and idiomatic patterns.
- Use **dependency injection** and contract bindings via Service Providers.
- Use dedicated **service classes** for complex domain workflows (`LicenseActivationService`, `LicenseVerifier`, etc.).
- Maintain **thin controllers** that delegate business logic to services and return structured JSON or View responses.
- Enforce strict typing, return types, and robust exception hierarchies.

## 3. Security & Operational Boundaries
- **Honest Threat Modeling:** Never claim PHP client-side enforcement is unbypassable. Host-level opcode manipulation, AST patching, and runtime debugger hooks are inherent boundaries on untrusted infrastructure.
- **Resilience Against False Positives:** Never treat a missing heartbeat as definitive proof of tampering or license theft (allow offline grace periods).
- **No Self-DoS or Untrusted Auto-Locking:** Never automatically lock customers based solely on untrusted client event reports (`/api/v1/security-events`).
- **No Backdoors:** Never implement hidden recovery backdoors or unauthenticated master bypass keys. All recovery paths must be cryptographically verified.
- **Zero Credential Exposure:** Never commit production credentials, `.env` files, or private signing keys to Git. Use placeholders in documentation.
- Review security implications and attack vectors prior to any code implementation.

## 4. Development & Pair Programming Workflow
- **Inspect First:** Always inspect existing code and file structures before modifying them.
- **Step-by-Step Development:** Break complex tasks into verifiable phases.
- **Verify with Tests:** Write automated tests for all features and security fixes. Run test suites after every significant change and fix all errors before declaring completion.
- **Slash Command Conventions:**
  - `/grill-me`: Align on requirements and resolve design decisions through structured questions.
  - `/plan`: Create comprehensive step-by-step implementation plans before modifying code.
  - `/boost`: Deep thinking, formal verification, and security reviews for cryptography and sensitive logic.
  - `/goal`: Autonomous execution of approved plans with verification.
  - `/teamwork`: Coordinate independent, parallel agent reviews without conflicting file changes.
  - `/browser`: Interactive UI, browser, and visual regression testing.
  - `/compact`: Summarize context when conversation trajectory becomes long.

