# Security Audit Report: apple-docs-mcp

**Package:** `@kimsungwhee/apple-docs-mcp` v1.0.26
**Audit Date:** 2026-02-12
**Scope:** Security analysis for users of this MCP server
**Auditor:** Automated security review

---

## Executive Summary

This MCP server provides Apple Developer Documentation search and WWDC video browsing capabilities to AI assistants (Claude, Cursor, etc.) via the Model Context Protocol. The server is **read-only** (no file writes, no command execution) and makes outbound HTTP requests exclusively to `developer.apple.com`. Overall, the server presents a **low-to-moderate risk profile** for end users, with several findings that range from informational to medium severity.

**Critical findings: 0**
**High findings: 1**
**Medium findings: 4**
**Low findings: 4**
**Informational findings: 3**

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

A malicious MCP client or prompt injection attack could supply path traversal payloads like `topicId: "../../etc/passwd"` or `videoId: "../../../.env"` to read arbitrary files from the host filesystem. While the Zod schemas validate that `year` and `videoId` are strings, they do **not** validate that the values are free of path separators (`../`).

**Impact:** An attacker who can control tool arguments (via prompt injection into the AI model) could read arbitrary files on the user's machine, including environment variables, SSH keys, credentials, and other sensitive data.

**Recommendation:**
- Validate `year`, `videoId`, and `topicId` against strict allowlists or patterns (e.g., `year` must match `/^\d{4}$/`, `videoId` must match `/^\d+$/`, `topicId` must match `/^[a-z0-9-]+$/`).
- Use `path.resolve()` and verify the resolved path starts with the expected base directory before reading.

---

### MED-1: Insufficient URL Validation Allows Broader Request Scope

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

While the `isValidAppleDeveloperUrl()` in `url-converter.ts` properly checks `hostname === 'developer.apple.com'`, it is only called in `getAppleDocContent()` in `index.ts`. Other code paths like `fetchAppleDocJson()` and internal reference-following use the weaker check.

Additionally, when `fetchAppleDocJson()` follows references recursively (line 308-315), it constructs new URLs from data returned by Apple's API without validating the constructed URL:

```typescript
const refUrl = `https://developer.apple.com/tutorials/data/documentation/${refPath}.json`;
return await fetchAppleDocJson(refUrl, options, maxDepth - 1);
```

The `refPath` comes from `mainReference.url` in the API response, which could potentially be manipulated via a response poisoning scenario.

**Impact:** In a prompt injection scenario, an attacker could potentially trick the MCP server into making requests to arbitrary URLs, enabling SSRF or data exfiltration.

**Recommendation:**
- Replace the `includes()` check in `fetchAppleDocJson()` with the proper `isValidAppleDeveloperUrl()` hostname check.
- Validate all constructed URLs before making HTTP requests.

---

### MED-2: Unbounded Memory Consumption via Cache Poisoning

**Severity:** MEDIUM
**Location:** `src/utils/cache.ts:1-160`
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

**Description:**
The in-memory caching system stores response data without any limit on individual entry size. Combined across all cache instances, the server can hold:

- `apiCache`: 500 entries
- `searchCache`: 200 entries
- `indexCache`: 100 entries
- `technologiesCache`: 50 entries
- `updatesCache`: 100 entries
- `sampleCodeCache`: 100 entries
- `technologyOverviewsCache`: 100 entries
- `wwdcDataCache`: 100 entries

There are no bounds on the size of individual cached values. If an Apple API response (or a crafted one in an SSRF scenario) returns an extremely large payload, it could cause the Node.js process to consume excessive memory, leading to denial of service for the user's machine.

Furthermore, the `setInterval` cleanup timer in the cache constructor runs indefinitely and is not cleaned up on server shutdown, which could lead to resource leaks.

**Impact:** A degraded performance or out-of-memory crash on the user's machine.

**Recommendation:**
- Add maximum size limits per cached value.
- Track total memory usage across caches.
- Clean up the `setInterval` timer reference on shutdown.

---

### MED-3: User-Agent Spoofing and TOS Violation Risk

**Severity:** MEDIUM (Operational)
**Location:** `src/utils/constants.ts:66-101`, `src/utils/http-client.ts`, `src/utils/http-headers-generator.ts`, `src/utils/user-agent-pool.ts`
**CWE:** N/A (Terms of Service / Ethical concern)

**Description:**
The server implements a sophisticated browser impersonation system:

1. **25 Safari User-Agent strings** covering multiple macOS versions
2. **User-Agent pool rotation** with `random`, `sequential`, and `smart` strategies
3. **Full browser header simulation** including `Sec-Fetch-*`, `Accept-Language` rotation, and DNT headers
4. **Automatic failure recovery** that marks User-Agents as failed and rotates to working ones

This system is explicitly designed to make HTTP requests appear as if they originate from real Safari browsers to avoid detection by Apple's servers. The code comments confirm this intent:

> "Smart User-Agent pool rotation with automatic failure recovery"
> "Dynamic browser headers generation... to avoid detection and improve API reliability"

**Impact:** Users running this MCP server may unknowingly violate Apple's Terms of Service for developer.apple.com, which could result in IP bans or account restrictions. The aggressive rotation and failure-recovery mechanisms could also be interpreted as automated scraping. If Apple blocks the user's IP address, it could affect their legitimate developer account access.

**Recommendation:**
- Users should be aware they are making automated requests disguised as browser traffic to Apple's servers.
- Consider using a static, honest User-Agent string that identifies the tool (e.g., `apple-docs-mcp/1.0.26`).
- Alternatively, use Apple's official APIs if available.

---

### MED-4: Error Messages Leak Internal State

**Severity:** MEDIUM
**Location:** `src/utils/error-handler.ts:38-89`, `src/tools/doc-fetcher.ts:326-349`
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

**Description:**
Error responses include raw error messages, internal URLs, and stack traces that are passed back to the AI model as tool results:

```typescript
// error-handler.ts:73
suggestions: [
  'Visit the original URL directly: ${url}',
]

// doc-fetcher.ts:344
text: `Error: Failed to get Apple doc content: ${errorMessage}\n\nPlease try accessing the documentation directly at: ${url}`,
```

When errors occur, raw exception messages from Node.js, the HTTP client, or filesystem operations are included in the response. These could expose:
- Internal file paths (from WWDC data loading errors)
- Network topology information
- Server-side error details

Since MCP tool responses are consumed by AI models which may include this information in their responses to users, sensitive internal details could be disclosed.

**Impact:** Information leakage of internal paths and server state via error messages.

**Recommendation:**
- Return sanitized, user-friendly error messages.
- Log detailed error information internally only.
- Avoid exposing raw filesystem paths or error stack traces in tool responses.

---

### LOW-1: No Input Length Limits on Search Queries

**Severity:** LOW
**Location:** `src/schemas/search.schema.ts:3-7`
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

**Description:**
The `searchAppleDocsSchema` defines `query` as `z.string()` with no maximum length constraint:

```typescript
export const searchAppleDocsSchema = z.object({
  query: z.string().describe('Search query'),
  type: z.enum(['all', 'documentation', 'sample']).default('all'),
});
```

An extremely long query string would be URL-encoded and sent to Apple's search endpoint, potentially causing request timeouts or excessive memory usage during URL construction and response parsing.

Similarly, the `searchWWDCContentSchema` has `query: z.string().min(1)` but no max length.

**Recommendation:**
- Add `.max(500)` or similar length limits to all string inputs in Zod schemas.

---

### LOW-2: Recursive Reference Following Without Full Depth Control

**Severity:** LOW
**Location:** `src/tools/doc-fetcher.ts:296-316`
**CWE:** CWE-674 (Uncontrolled Recursion)

**Description:**
The `fetchAppleDocJson()` function recursively follows references in API responses:

```typescript
if (!jsonData.primaryContentSections &&
    jsonData.references && maxDepth > 0) {
  const refUrl = `...`;
  return await fetchAppleDocJson(refUrl, options, maxDepth - 1);
}
```

While `maxDepth` defaults to 2, which limits recursion, the parameter is not validated against being set to an excessively large value from the tool call. The function accepts `maxDepth` as a number without bounds.

**Impact:** Minimal - the current default of 2 is safe, and the parameter is not directly exposed to MCP tool arguments. However, if the API is extended to expose this parameter, it could enable resource exhaustion.

**Recommendation:**
- Cap `maxDepth` to a maximum value (e.g., 5) regardless of input.

---

### LOW-3: Sensitive Environment Variable Accepted Without Documentation

**Severity:** LOW
**Location:** `src/utils/http-client.ts:102-108`
**CWE:** CWE-1188 (Insecure Default Initialization of Resource)

**Description:**
The HTTP headers generator reads multiple environment variables:

```typescript
const config: HeaderGeneratorConfig = {
  enableSecFetch: process.env.DISABLE_SEC_FETCH !== 'true',
  enableDNT: process.env.DISABLE_DNT !== 'true',
  languageRotation: process.env.DISABLE_LANGUAGE_ROTATION !== 'true',
  simpleMode: process.env.SIMPLE_HEADERS_MODE === 'true',
  defaultAcceptLanguage: process.env.DEFAULT_ACCEPT_LANGUAGE || 'en-US,en;q=0.9',
};
```

And the User-Agent pool is configurable via `USER_AGENT_POOL_CONFIG` which accepts custom pool configuration as JSON. None of these environment variables are documented in the README or validated for correctness. The `USER_AGENT_POOL_CONFIG` variable is particularly concerning as it accepts arbitrary JSON.

**Recommendation:**
- Document all accepted environment variables.
- Validate environment variable values (especially JSON inputs).

---

### LOW-4: `setInterval` Timer Leak

**Severity:** LOW
**Location:** `src/utils/cache.ts:19`, `src/index.ts:308`
**CWE:** CWE-404 (Improper Resource Shutdown or Release)

**Description:**
Each `MemoryCache` instance creates a `setInterval` for cleanup that runs every 5 minutes. With 8 cache instances, this creates 8 perpetual timers. The `schedulePeriodicCacheRefresh()` creates another timer. None of these timers are cleaned up on server shutdown, which can prevent clean process exit and cause resource leaks during testing.

**Recommendation:**
- Store interval references and clear them on shutdown.
- Use `unref()` on timers to prevent them from keeping the process alive.

---

### INFO-1: No Authentication or Authorization on MCP Tools

**Severity:** INFORMATIONAL
**Location:** `src/index.ts`, `src/tools/handlers.ts`

**Description:**
The MCP server exposes all tools without any authentication or authorization controls. Any MCP client that connects can invoke any tool. This is standard for local MCP servers using stdio transport, but users should understand that:

1. Any AI model connected to this server can make arbitrary Apple Developer Documentation requests on their behalf.
2. The `get_performance_report` and `get_cache_stats` tools expose internal server metrics.
3. There is no rate limiting per client - only a global rate limit of 100 requests/minute.

**Impact:** Standard for MCP architecture. Users should be aware that connecting this server grants the AI model full access to all tools.

---

### INFO-2: Dependencies Are Minimal and Reputable

**Severity:** INFORMATIONAL
**Location:** `package.json`

**Description:**
The production dependency surface is minimal:
- `@modelcontextprotocol/sdk` ^1.15.1 - Official MCP SDK
- `cheerio` ^1.1.0 - HTML parsing (well-maintained, widely used)
- `zod` ^4.0.5 - Schema validation (well-maintained, widely used)

All three are reputable, actively maintained packages. The use of caret (`^`) version ranges means minor/patch updates will be automatically applied, which could theoretically introduce supply chain vulnerabilities, but this is standard npm practice.

**Recommendation:**
- Consider using a lockfile (`pnpm-lock.yaml` is present) and auditing it periodically.
- Run `npm audit` regularly.

---

### INFO-3: No Network Egress Restrictions Beyond Apple

**Severity:** INFORMATIONAL
**Location:** `src/utils/http-client.ts`

**Description:**
While the URL validation in `index.ts` checks for `developer.apple.com`, the HTTP client itself (`httpClient.get()`, `httpClient.getText()`, `httpClient.getJson()`) has no domain restrictions. If a bypass of the URL validation is found (see MED-1), the HTTP client will happily make requests to any domain.

The HTTP client also leaks information about the user's environment through its requests:
- IP address
- Network topology (through connection patterns)
- Timing information

**Recommendation:**
- Implement domain allowlisting at the HTTP client level as defense in depth.

---

## Threat Model Summary

| Threat | Risk Level | Mitigated? |
|--------|-----------|------------|
| Arbitrary file read via path traversal | HIGH | No |
| SSRF via URL validation bypass | MEDIUM | Partially |
| Memory exhaustion via large responses | MEDIUM | No |
| Apple TOS violation / IP ban | MEDIUM | No |
| Prompt injection leading to tool abuse | MEDIUM | Partially (Zod schemas) |
| Information leakage via error messages | MEDIUM | No |
| Denial of service via resource exhaustion | LOW | Partially (rate limiter) |
| Supply chain compromise | LOW | Partially (minimal deps) |

---

## Positive Security Aspects

1. **Read-only operation:** The server does not write files, execute commands, or modify any state on disk.
2. **Zod schema validation:** All tool inputs are validated through Zod schemas before processing.
3. **Rate limiting:** A global rate limiter caps requests at 100/minute.
4. **Minimal dependencies:** Only 3 production dependencies, all well-maintained.
5. **No credential storage:** The server does not handle or store any user credentials.
6. **Stdio transport:** Uses local stdio communication, not exposed to the network.
7. **URL validation present:** The `isValidAppleDeveloperUrl()` function properly validates hostnames (though not used consistently).
8. **Retry limits:** HTTP retries are capped at 3 attempts with exponential backoff.

---

## Recommendations Summary (Priority Order)

1. **[HIGH]** Add path traversal protection to WWDC data loading functions by validating `year`, `videoId`, and `topicId` against strict regex patterns and verifying resolved paths are within the data directory.
2. **[MEDIUM]** Standardize URL validation to use `isValidAppleDeveloperUrl()` (hostname check) everywhere, not just in the top-level handler.
3. **[MEDIUM]** Add per-entry size limits to the caching system.
4. **[MEDIUM]** Sanitize error messages before returning them as tool responses.
5. **[LOW]** Add maximum length constraints to all string inputs in Zod schemas.
6. **[LOW]** Document all environment variables and validate their values.
7. **[LOW]** Fix timer cleanup on shutdown.
