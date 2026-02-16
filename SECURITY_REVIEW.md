# Security Review: py-kube-downscaler

**Date:** 2026-02-16
**Scope:** Full repository review — Python source, Dockerfile, Helm chart, CI/CD workflows, dependencies

---

## Executive Summary

py-kube-downscaler is a Kubernetes operator that automatically scales down workloads during non-work hours. The codebase is relatively well-structured with good security defaults in the Helm chart (non-root user, read-only filesystem, dropped capabilities). However, the review identified several issues ranging from policy injection risks to logic bugs that could cause availability problems.

**Critical: 0 | High: 1 | Medium: 3 | Low: 4 | Informational: 5**

---

## Findings

### HIGH-1: Rego/Kyverno Policy Injection via Unsanitized User Input

**Severity:** HIGH
**Files:**
- `kube_downscaler/resources/constrainttemplate.py:15,33-37`
- `kube_downscaler/resources/policy.py:146-148,160-164`

**Description:**
User-supplied regex patterns from `--matching-labels` and job names from `--exclude-deployments` are concatenated directly into Rego code (Gatekeeper) and JMESPath expressions (Kyverno) without any sanitization or escaping.

In `constrainttemplate.py`:
```python
excluded_jobs_regex = "^(" + "|".join(excluded_jobs) + ")$"
# ...
matching_labels_rego_string = (
    '    has_matched_labels("' + pattern.pattern + '", input.review.object.metadata.labels)\n'
)
```

In `policy.py`:
```python
"key": "{{ regex_match('" + pattern.pattern + "', '{{element.key}}={{element.value}}') }}"
```

**Impact:**
These values are embedded into admission controller policies deployed cluster-wide. A value containing `"`, `\`, or Rego/JMESPath syntax characters could alter policy logic, potentially allowing jobs to bypass downscaling restrictions or causing policy evaluation errors that block all job creation in affected namespaces.

**Recommendation:**
- Escape special characters in `pattern.pattern` and `excluded_jobs` before embedding them into Rego strings and Kyverno expressions.
- For Rego: escape `"` and `\` characters at minimum.
- For Kyverno JMESPath: validate that patterns contain only regex-safe characters (alphanumeric, `-`, `_`, `=`, `.`, `*`, `+`, `?`, `|`, `^`, `$`, `(`, `)`, `[`, `]`).
- Consider validating patterns against an allowlist of safe characters at parse time in `cmd.py`.

---

### MEDIUM-1: Uncontrolled Regex Compilation — ReDoS and Crash Risk

**Severity:** MEDIUM
**Files:**
- `kube_downscaler/main.py:118,132`
- `kube_downscaler/scaler.py:291`

**Description:**
Regex patterns from environment variables (`EXCLUDE_NAMESPACES`, `MATCHING_LABELS`) and CLI arguments are compiled with `re.compile()` without validation or complexity limits:

```python
exclude_namespaces=frozenset(
    re.compile(pattern) for pattern in exclude_namespaces.split(",")
),
matching_labels=frozenset(
    re.compile(pattern) for pattern in matching_labels.split(",")
),
```

**Impact:**
- A malicious or misconfigured regex (e.g., `(a+)+$`) causes catastrophic backtracking (ReDoS) when evaluated against resource names in every scaling cycle, starving CPU.
- An invalid regex pattern crashes the main loop with an unhandled `re.error` exception.
- These regexes are evaluated against every resource name/label in the cluster on each interval, amplifying the impact.

**Recommendation:**
- Wrap `re.compile()` calls in try/except and fail fast with a clear error on startup.
- Consider setting a maximum pattern length or using `re.compile()` with a timeout (via the `regex` library's `timeout` parameter) as a defense against ReDoS.
- Validate patterns at argument parse time in `cmd.py` rather than deferring to the main loop.

---

### MEDIUM-2: Token Bucket Initialization Logic Bug — Potential Infinite Hang

**Severity:** MEDIUM
**File:** `kube_downscaler/helper.py:255-259`

**Description:**
```python
def initialize_token_bucket(qps, burst):
    global TOKEN_BUCKET
    if qps == 0 and burst == 0:
        TOKEN_BUCKET = None
    TOKEN_BUCKET = TokenBucket(qps=qps, burst=burst)
```

The `if` branch sets `TOKEN_BUCKET = None` but then falls through (missing `return` or `else`) and overwrites it with `TokenBucket(qps=0, burst=0)`. The `TokenBucket.acquire()` method with `qps=0` and `burst=0` skips the refill loop body (`if self.qps > 0 and self.burst > 0` is False), so `acquire()` returns immediately without rate limiting. However, if `qps=0` and `burst>0`, or `qps>0` and `burst=0`, the token bucket enters a state where tokens are never refilled or the bucket capacity is zero, causing the `while True` loop to spin indefinitely.

While `main.py` validates `burst >= qps`, it does not prevent `qps=0, burst=0` or other degenerate combinations.

**Impact:** A configuration error could cause the downscaler process to hang indefinitely on the first API call.

**Recommendation:**
- Add `return` after `TOKEN_BUCKET = None` (or use `else`).
- Validate that both `qps` and `burst` are either both zero (disabled) or both positive at startup.

---

### MEDIUM-3: CLI Arguments Logged at Startup Without Filtering

**Severity:** MEDIUM
**File:** `kube_downscaler/main.py:36-37`

**Description:**
```python
config_str = ", ".join(f"{k}={v}" for k, v in sorted(vars(args).items()))
logger.info(f"Downscaler v{__version__} started with {config_str}")
```

All parsed CLI arguments are dumped to the log at INFO level. While current arguments don't contain secrets, this pattern is fragile — any future argument containing sensitive data (API keys, tokens, internal hostnames) would be logged in plaintext.

**Impact:** Potential exposure of sensitive configuration values in centralized logging systems.

**Recommendation:**
- Log only non-sensitive arguments, or maintain an explicit allowlist of argument names to include in the startup log.
- At minimum, redact any arguments whose names contain patterns like `token`, `secret`, `key`, `password`.

---

### LOW-1: `Retry-After` Header Parsed Without Lower Bound

**Severity:** LOW
**File:** `kube_downscaler/helper.py:323-352`

**Description:**
The `Retry-After` HTTP header value is capped at `max_delay` (60s) but has no lower bound:

```python
delay = min(delay, max_delay)
```

If `Retry-After` is `0`, the retry happens immediately with no backoff. If the header contains a past HTTP date, `delay` becomes negative, and `time.sleep(negative_value)` raises `ValueError`, which propagates as an unhandled exception.

**Recommendation:** Add `delay = max(0.1, min(delay, max_delay))` to enforce a minimum delay.

---

### LOW-2: Broad Exception Handling Masks Errors in Main Loop

**Severity:** LOW
**File:** `kube_downscaler/main.py:135-136`

**Description:**
```python
except Exception as e:
    logger.exception(f"Failed to autoscale: {e}")
```

The bare `except Exception` catches everything including `KeyboardInterrupt`-adjacent errors, `MemoryError`, and programming bugs like `TypeError` or `AttributeError`. This means configuration errors, code bugs, and transient API failures all get the same treatment: log and retry on the next interval.

**Recommendation:** Catch more specific exception types (e.g., `requests.RequestException`, `pykube.exceptions.HTTPError`) and let unexpected exceptions propagate for visibility.

---

### LOW-3: Kubernetes Annotation Values Not Validated Before Use

**Severity:** LOW
**File:** `kube_downscaler/scaler.py` (multiple locations)

**Description:**
Annotation values from Kubernetes resources (which any namespace-scoped user can set) are read and passed directly to business logic:

```python
uptime = resource.annotations.get(UPTIME_ANNOTATION, default_uptime)
downtime = resource.annotations.get(DOWNTIME_ANNOTATION, default_downtime)
```

A malicious annotation value like `downscaler/uptime: "(a+)+$"` would be passed to `matches_time_spec()`, which would trigger ReDoS on the regex-based time spec parser. A malformed timezone string in an annotation triggers `pytz.exceptions.UnknownTimeZoneError`, caught by the broad exception handler.

**Recommendation:** Validate annotation values against expected formats before passing them to parsing functions. Apply length limits and character restrictions.

---

### LOW-4: `--admission-controller` Not Validated at Parse Time

**Severity:** LOW
**File:** `kube_downscaler/cmd.py:151-154`

**Description:**
The `--admission-controller` argument accepts arbitrary strings. An invalid value like `--admission-controller=istio` is only detected deep in `autoscale_jobs()` where it logs a warning and silently skips job scaling.

**Recommendation:** Add `choices=["", "gatekeeper", "kyverno"]` to the argparse definition to catch invalid values at startup.

---

### INFO-1: Dockerfile Uses Different Alpine Versions in Stages

**Severity:** INFORMATIONAL
**File:** `Dockerfile:1,16`

**Description:**
```dockerfile
FROM python:3.12.12-alpine3.23 AS builder  # Stage 1
FROM python:3.12.12-alpine3.22             # Stage 2 (runtime)
```

The builder uses Alpine 3.23 and the runtime uses Alpine 3.22. While the runtime image only copies Python `site-packages` (not native libraries), this version mismatch could cause subtle ABI incompatibilities if any dependency includes compiled C extensions linked against different libc versions.

**Recommendation:** Use the same Alpine version in both stages.

---

### INFO-2: Container Security Defaults Are Well Configured

**Severity:** INFORMATIONAL (Positive Finding)
**File:** `chart/values.yaml:38-51`

The Helm chart ships with strong security defaults:
- `runAsNonRoot: true` with UID/GID 1000
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- Resource limits defined (CPU 500m, memory 900Mi)

This is a good practice and follows Kubernetes security best practices.

---

### INFO-3: RBAC Follows Least Privilege for Constrained Mode

**Severity:** INFORMATIONAL (Positive Finding)
**File:** `chart/templates/rbac.yaml`

The chart supports two RBAC modes:
- **Cluster-wide mode:** Uses ClusterRole/ClusterRoleBinding with access to all namespaces.
- **Constrained mode:** Uses namespace-scoped Role/RoleBinding, limiting access to only the configured namespaces.

The Kyverno policy RBAC uses `resourceNames` to scope policy management to only `kube-downscaler-jobs-policy`, which is a good practice.

**Note:** The cluster-wide ClusterRole includes `create` on `customresourcedefinitions` (apiextensions.k8s.io), which is a powerful permission. This is needed for Gatekeeper constraint template management but should be documented as a privilege escalation vector.

---

### INFO-4: CI/CD Pipeline Fetches Helm via Unauthenticated curl|bash

**Severity:** INFORMATIONAL
**Files:**
- `.github/workflows/end2end.yml:35-36`
- `.github/workflows/helm-build.yml:20-21`

**Description:**
```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

This pattern fetches and executes a script from the internet without integrity verification. While this is a common pattern in CI/CD and the risk is mitigated by GitHub Actions' ephemeral runners, it's still a supply chain risk if the upstream script is compromised.

**Recommendation:** Pin Helm installation to a specific version using the official `azure/setup-helm` GitHub Action, or verify the script's checksum before execution.

---

### INFO-5: Cosign Installer Pinned to `@main` Branch

**Severity:** INFORMATIONAL
**File:** `.github/workflows/docker-build.yml:49-51`

**Description:**
```yaml
uses: sigstore/cosign-installer@main
with:
  cosign-release: "v2.2.0"
```

While the Cosign binary version is pinned to `v2.2.0`, the installer action itself references the `@main` branch, meaning the installation mechanism could change at any time.

**Recommendation:** Pin the action to a specific version tag or commit SHA (e.g., `sigstore/cosign-installer@v3.5.0`).

---

## Dependency Analysis

| Dependency | Version | Notes |
|---|---|---|
| `new-pykube` | unpinned (`*`) | Kubernetes API client. No pinned version — vulnerable to supply chain attacks if a malicious version is published. `poetry.lock` mitigates this for builds from source. |
| `pytz` | unpinned (`*`) | Timezone library. Same unpinning concern. Consider migrating to `zoneinfo` (stdlib in Python 3.9+). |
| Python | 3.12.12 | Current and well-maintained. |
| Alpine | 3.22/3.23 | Recent versions with active security updates. |

**Recommendation:** Pin runtime dependency versions in `pyproject.toml` to specific ranges (e.g., `new-pykube = "^0.23"`) rather than `*` to prevent unexpected breaking changes or supply chain compromise. The `poetry.lock` file provides deterministic builds but only when `poetry install` is used.

---

## Summary of Recommendations

### Priority 1 (Should Fix)
1. **Sanitize user input before embedding in Rego/Kyverno policies** (HIGH-1) — Escape or validate pattern strings before string concatenation into policy code.
2. **Fix token bucket initialization logic bug** (MEDIUM-2) — Add `return` after `TOKEN_BUCKET = None`.
3. **Validate regex patterns at startup** (MEDIUM-1) — Wrap `re.compile()` in try/except at argument parsing time; consider complexity limits.

### Priority 2 (Should Improve)
4. **Add lower bound to Retry-After delay** (LOW-1) — Prevent negative sleep and tight retry loops.
5. **Validate `--admission-controller` at parse time** (LOW-4) — Use `choices` in argparse.
6. **Align Alpine versions in Dockerfile** (INFO-1) — Use same Alpine version in both stages.
7. **Pin CI/CD action versions** (INFO-4, INFO-5) — Avoid `@main` and `curl|bash` patterns.

### Priority 3 (Nice to Have)
8. **Filter sensitive args from startup log** (MEDIUM-3) — Use allowlist for logged arguments.
9. **Validate annotation values** (LOW-3) — Add format/length checks before parsing.
10. **Pin dependency versions** (Deps) — Use version ranges instead of `*`.
11. **Consider migrating from pytz to zoneinfo** (Deps) — stdlib alternative available since Python 3.9.
