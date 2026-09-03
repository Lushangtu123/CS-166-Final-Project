# Public Deployment Hardening Design

## Goal

Make the phishing-analysis application safe to expose as a public service while preserving the full email-authenticity verifier for users who deliberately deploy it on their own computers.

## Scope

This change covers three maintenance risks identified during the repository audit:

1. Disable high-risk outbound email verification by default.
2. Prevent production from silently training on synthetic data.
3. Add repeatable automated checks and continuous integration.

The existing email-address analysis, content analysis, static frontend, and local full-verifier implementation remain in scope. Authentication, hosted databases, distributed rate limiting, and provider-specific deployment files are out of scope.

## Runtime Modes

The application will use explicit environment configuration:

- `APP_ENV=production` selects public-service behavior.
- `ENABLE_EMAIL_VERIFICATION=false` is the default in every environment.
- `ALLOW_SYNTHETIC_DATA=false` is the default. Developers may set it to `true` only for local experimentation.

Public deployments must keep email verification disabled. Users who want the complete SMTP, DNS, PTR, SPF, DMARC, and WHOIS workflow must run the application on their own computer and explicitly enable it.

## Components and Behavior

### Verification feature gate

The backend will expose a small public configuration response indicating whether full verification is enabled. When disabled, `/api/verify-email` will reject requests without starting DNS, SMTP, WHOIS, or other outbound work. The frontend will hide the verification controls and show a short notice that the complete version requires local deployment.

The existing verifier code will remain available behind the feature gate for intentional local use. Environment parsing will be strict and centralized so values such as `1`, `true`, `yes`, and `on` are handled consistently.

### Dataset safety

Startup will load the real cached UCI dataset when present. If it is missing, startup will fail with an actionable error unless `ALLOW_SYNTHETIC_DATA=true` is explicitly set. Production will reject synthetic-data mode even if it is requested accidentally.

The health response will report whether the model is loaded and whether it was trained from real or synthetic data, without exposing local paths or secrets.

### Dependency and deployment documentation

Dependency files will receive bounded compatible version ranges rather than unbounded lower limits. The README will document safe public defaults and a separate local-only full-version command. An example environment file will list non-secret settings.

### Automated checks

Tests will use Python's standard `unittest` where practical and Node's built-in test runner for frontend behavior, avoiding a new test-framework dependency. GitHub Actions will install the project dependencies, run Python tests, run the frontend tests, check JavaScript syntax, and compile Python sources.

## Data Flow

For public deployments:

1. The server reads and validates environment configuration at startup.
2. The model loads only from real data.
3. The frontend reads the public feature configuration.
4. Email-address and content-analysis requests stay local to the process.
5. Verification requests are rejected before any outbound lookup or connection.

For explicitly enabled local deployments, the existing verification endpoint may perform its documented outbound checks. The UI will clearly label this as a local-only capability.

## Error Handling

- Invalid Boolean environment values fail startup with the variable name and accepted forms.
- Missing real model data fails startup with instructions for supplying data or explicitly enabling local synthetic mode.
- Disabled verification returns a stable HTTP error and performs no network work.
- The frontend treats a disabled verification response as an expected state rather than a generic request failure.

## Test Strategy

Implementation will follow red-green-refactor cycles for:

- strict environment parsing;
- verification disabled by default;
- disabled verification short-circuiting before outbound functions run;
- production rejection of synthetic-data mode;
- missing real data failure and explicit local synthetic fallback;
- frontend visibility and local-deployment notice;
- the previously added category singular/plural regression test.

Final verification will include all new tests, JavaScript syntax checking, Python syntax compilation, and a clean diff check. Full model training and live SMTP/WHOIS probes are not required in CI because they depend on large external datasets and third-party network behavior.

## Acceptance Criteria

- A default public-style startup cannot perform email verification.
- Public production mode cannot silently use synthetic training data.
- The UI tells users that the full version requires deployment on their own computer.
- Tests demonstrate both safe defaults and explicit local opt-in behavior.
- CI runs the repository's repeatable checks on every push and pull request.
- Existing unrelated changes are preserved.
