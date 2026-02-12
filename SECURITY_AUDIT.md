# Security Audit Report: apple-docs-mcp

**Package:** `@kimsungwhee/apple-docs-mcp` v1.0.26
**Audit Date:** 2026-02-12
**Scope:** Security analysis for users of this MCP server
**Auditor:** Automated security review

---

## Executive Summary

This MCP server provides Apple Developer Documentation search and WWDC video browsing capabilities to AI assistants (Claude, Cursor, etc.) via the Model Context Protocol. The server is **read-only** (no file writes, no command execution) and makes outbound HTTP requests to `developer.apple.com`.

**Important context:** Apple does not provide an official public API for querying developer documentation. The only way to programmatically access this content is through Apple's undocumented web endpoints and HTML pages. The browser header simulation in this server is a necessary design choice, not a security defect.

With that context, the audit focuses on findings that pose **real risk to users**: arbitrary file reads, request forgery, and resource exhaustion.

**High findings: 1** (path traversal — real exploit risk)
**Medium findings: 1** (SSRF via URL validation bypass — real exploit risk)
**Low findings: 5** (robustness and quality issues)
**Informational findings: 4** (design trade-offs and context)

---

## Findings

### HIGH-1: Path Traversal in WWDC Data Loading

**Severity:** HIGH
**Location:** `src/utils/wwdc-data-source.ts:22-33`, `src/tools/wwdc/wwdc-handlers.ts:20-34`
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

**Description:**
The `loadVideoData()`, `loadTopicIndex()`, and `loadYearIndex()` functions accept user-controlled `year`, `videoId`, and `topicId` parameters that are interpolated directly into file paths without sanitization:

```typescript
// wwdc-data-source.ts:102
async function loadVideoData(year: string, videoId: string): Promise<WWDCVideo> {
  const data = await fetchData(`videos/${year}-${videoId}.json`);
  // ...
}

// wwdc-data-source.ts:74
async function loadTopicIndex(topicId: string): Promise<TopicIndex> {
  const data = await fetchData(`by-topic/${topicId}/index.json`);
  // ...
}
```

The `fetchData` function joins these with the base data directory via `path.join()`:

```typescript
async function readBundledFile(filePath: string): Promise<string> {
  const fullPath = path.join(WWDC_DATA_DIR, filePath);
  const content = await fs.readFile(fullPath, 'utf-8');
  // ...
}
```

A prompt injection attack could supply path traversal payloads like `topicId: "../../etc/passwd"` or `videoId: "../../../.ssh/id_rsa"` to read arbitrary files from the host filesystem. The Zod schemas only validate that these are strings — they do **not** reject path separators (`../`).

**Attack scenario:** An attacker embeds a prompt injection in a webpage or document that the AI model processes. The injection instructs the model to call `get_wwdc_video` with `year: "2024"` and `videoId: "../../../../.env"`. The server reads the file and returns its contents to the AI model, which the attacker can then exfiltrate.

**Impact:** Arbitrary file read on the user's machine. An attacker could steal SSH keys, environment variables with API tokens, credentials files, and other sensitive data.

**Recommendation:**
- Validate `year` against `/^\d{4}$/`
- Validate `videoId` against `/^\d+$/`
- Validate `topicId` against `/^[a-z0-9-]+$/`
- As defense in depth: resolve the full path with `path.resolve()` and verify it starts with `WWDC_DATA_DIR` before reading.

---

### MED-1: SSRF via Insufficient URL Validation

**Severity:** MEDIUM
**Location:** `src/tools/doc-fetcher.ts:268`, `src/utils/url-converter.ts:55-62`
**CWE:** CWE-918 (Server-Side Request Forgery)

**Description:**
The `fetchAppleDocJson()` function validates the URL with a simple `includes()` check:

```typescript
if (!url.includes('developer.apple.com')) {
  throw new Error('URL must be from developer.apple.com');
}
```

This is bypassable with URLs like:
- `https://evil.com/?q=developer.apple.com`
- `https://developer.apple.com.evil.com/path`
- `https://evil.com/developer.apple.com`

A proper hostname check exists (`isValidAppleDeveloperUrl()` in `url-converter.ts` uses `hostname === 'developer.apple.com'`), but it is only called in `getAppleDocContent()` in `index.ts`. The `fetchAppleDocJson()` function and its recursive reference-following code path use the weaker `includes()` check.

**Attack scenario:** Via prompt injection, the AI model is instructed to call `get_apple_doc_content` with a crafted URL that passes the weak check. The server makes an HTTP request to an attacker-controlled domain, potentially leaking the user's IP address, internal network information, or allowing the attacker to serve malicious content back through the tool response.

**Impact:** The server could be tricked into making requests to arbitrary domains from the user's machine.

**Recommendation:**
- Replace the `includes()` check in `fetchAppleDocJson()` with the proper `isValidAppleDeveloperUrl()` hostname check.
- Validate all constructed URLs (including recursive reference URLs) before making HTTP requests.
- As defense in depth: add domain allowlisting at the HTTP client level.

---

### LOW-1: Unbounded Individual Cache Entry Size

**Severity:** LOW
**Location:** `src/utils/cache.ts:1-160`
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

**Description:**
The caching system limits the number of entries per cache but not the size of individual values. An unusually large API response could consume significant memory. Combined across 8 cache instances (1,250 total entry slots), memory usage is theoretically unbounded per entry.

In practice this is unlikely to cause issues since responses come from Apple's servers, but if combined with the SSRF finding (MED-1), an attacker-controlled server could return very large payloads.

**Recommendation:**
- Add a maximum size check per cached value (e.g., reject values over 1MB).

---

### LOW-2: No Input Length Limits on Search Queries

**Severity:** LOW
**Location:** `src/schemas/search.schema.ts:3-7`
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

**Description:**
The `searchAppleDocsSchema` defines `query` as `z.string()` with no maximum length constraint. An extremely long query string would be URL-encoded and sent to Apple's endpoint, potentially causing timeouts.

**Recommendation:**
- Add `.max(500)` or similar length limits to string inputs in Zod schemas.

---

### LOW-3: Error Messages Expose Internal Paths

**Severity:** LOW
**Location:** `src/utils/error-handler.ts:38-89`, `src/tools/doc-fetcher.ts:326-349`
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

**Description:**
Error responses include raw exception messages from Node.js and filesystem operations that are returned to the AI model. These could expose internal file paths (e.g., from failed WWDC data loads). Since the server runs locally, the leaked paths are the user's own — this is low impact, but the paths could be useful to an attacker who has already achieved prompt injection and is trying to target specific files via HIGH-1.

**Recommendation:**
- Return sanitized, generic error messages in tool responses.
- Log detailed errors internally only.

---

### LOW-4: Sensitive Environment Variables Accepted Without Validation

**Severity:** LOW
**Location:** `src/utils/http-client.ts:102-108`
**CWE:** CWE-1188 (Insecure Default Initialization of Resource)

**Description:**
The server reads multiple undocumented environment variables (`DISABLE_SEC_FETCH`, `DISABLE_DNT`, `SIMPLE_HEADERS_MODE`, `USER_AGENT_POOL_CONFIG`, etc.). The `USER_AGENT_POOL_CONFIG` variable accepts arbitrary JSON without validation.

**Recommendation:**
- Document all accepted environment variables.
- Validate environment variable values.

---

### LOW-5: `setInterval` Timer Leak on Shutdown

**Severity:** LOW
**Location:** `src/utils/cache.ts:19`, `src/index.ts:308`
**CWE:** CWE-404 (Improper Resource Shutdown or Release)

**Description:**
8 cache instances each create a `setInterval` for cleanup (every 5 minutes), plus `schedulePeriodicCacheRefresh()` creates another timer. None are cleaned up on shutdown.

**Recommendation:**
- Store interval references and clear them on `SIGINT`/`SIGTERM`.
- Use `unref()` on timers.

---

### INFO-1: User-Agent Rotation Is a Necessary Design Choice

**Severity:** INFORMATIONAL
**Location:** `src/utils/constants.ts:66-101`, `src/utils/http-client.ts`, `src/utils/user-agent-pool.ts`

**Description:**
The server implements browser header simulation with 25 Safari User-Agent strings, rotation strategies, and `Sec-Fetch-*` header generation. **This is not a security vulnerability.** Apple does not provide an official public API for developer documentation. The only way to access this content programmatically is through Apple's web endpoints, which expect browser-like requests. Without this header simulation, the server would not function.

**User awareness:** Users should understand that this server makes automated requests to Apple's website disguised as browser traffic. While necessary, this could theoretically result in IP-level rate limiting by Apple if used excessively.

---

### INFO-2: No Authentication on MCP Tools (Standard for MCP)

**Severity:** INFORMATIONAL
**Location:** `src/index.ts`, `src/tools/handlers.ts`

**Description:**
All tools are exposed without authentication. This is standard for local MCP servers using stdio transport. Users should understand that connecting this server grants the AI model access to all tools, including `get_performance_report` and `get_cache_stats` which expose internal metrics.

---

### INFO-3: Dependencies Are Minimal and Reputable

**Severity:** INFORMATIONAL
**Location:** `package.json`

**Description:**
Only 3 production dependencies, all well-maintained:
- `@modelcontextprotocol/sdk` ^1.15.1
- `cheerio` ^1.1.0
- `zod` ^4.0.5

Low supply chain risk. A `pnpm-lock.yaml` lockfile is present.

---

### INFO-4: No Network Egress Restrictions at HTTP Client Level

**Severity:** INFORMATIONAL
**Location:** `src/utils/http-client.ts`

**Description:**
The HTTP client has no built-in domain restrictions. URL validation happens at the tool handler level. If the URL validation is bypassed (see MED-1), the client will make requests to any domain. Adding domain allowlisting at the client level would provide defense in depth.

---

## Threat Model Summary

| Threat | Risk Level | Exploitable? |
|--------|-----------|------------|
| Arbitrary file read via path traversal | **HIGH** | **Yes** — via prompt injection |
| SSRF via URL validation bypass | **MEDIUM** | **Yes** — via prompt injection |
| Memory exhaustion via large responses | LOW | Only if combined with SSRF |
| Error message path leakage | LOW | Aids exploitation of HIGH-1 |
| Denial of service via resource exhaustion | LOW | Partially mitigated (rate limiter) |
| Supply chain compromise | LOW | Minimal dependency surface |

---

## Positive Security Aspects

1. **Read-only operation:** The server does not write files, execute commands, or modify any state on disk.
2. **Zod schema validation:** All tool inputs are validated through Zod schemas before processing.
3. **Rate limiting:** A global rate limiter caps requests at 100/minute.
4. **Minimal dependencies:** Only 3 production dependencies, all well-maintained.
5. **No credential storage:** The server does not handle or store any user credentials.
6. **Stdio transport:** Uses local stdio communication, not exposed to the network.
7. **URL validation present:** A proper `isValidAppleDeveloperUrl()` function exists (but needs consistent use).
8. **Retry limits:** HTTP retries are capped at 3 attempts with exponential backoff.

---

## Recommendations Summary (Priority Order)

1. **[HIGH] Fix path traversal** — Validate `year`, `videoId`, and `topicId` against strict regex patterns. Verify resolved paths are within the data directory before reading.
2. **[MEDIUM] Fix URL validation** — Use `isValidAppleDeveloperUrl()` (hostname check) consistently in all code paths, not just the top-level handler. Add domain allowlisting at the HTTP client level.
3. **[LOW]** Add maximum length constraints to string inputs in Zod schemas.
4. **[LOW]** Sanitize error messages before returning them as tool responses.
5. **[LOW]** Add per-entry size limits to caches.
6. **[LOW]** Document environment variables and validate their values.
7. **[LOW]** Fix timer cleanup on shutdown.
