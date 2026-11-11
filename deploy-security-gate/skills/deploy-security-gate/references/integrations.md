# Integration review guide

Read only the sections for integrations in scope. Each one lists what good looks like, what to grep for and red flags. Report the red flags with file:line.

## Contents

- AI gateways and LLM providers (OpenAI, Anthropic, Bedrock, Vertex, Gemini, LiteLLM, Portkey, Vercel AI SDK, LangChain)
- MCP servers and agent tools
- Payments (Stripe, Razorpay, Adyen, PayPal, Paddle)
- Analytics, error tracking and session replay (Segment, PostHog, Mixpanel, Amplitude, GA, Sentry, Datadog)
- Auth providers and customer API keys

---

## AI gateways and LLM providers

**Good:**

- The client calls your backend route with the user's session.
- The backend checks auth, tenant, rate limit and token budget, picks the model from an allowlist, and calls the provider or gateway with a key from the secrets manager.
- Output is validated before use.
- A second provider or region is configured for failover.

**Look for:**

- SDK constructors (`new OpenAI(`, `new Anthropic(`, `BedrockRuntimeClient(`, `genai.Client(`) and the file they live in. They should only ever appear in server code.
- `model:` / `model=` values taken from `req.body`, query params or user input. That is a red flag unless validated against an allowlist.
- `max_tokens` / `max_output_tokens`: these must be set server-side, with a cap.
- Rate-limiting middleware on AI routes, keyed by user or tenant, not only by IP.
- Tool definitions and their handlers: which credentials does a handler use? It should use the end user's scoped token, not an admin or service key.
- Model output flowing into `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `exec`, SQL string building, `subprocess`, shell commands or `fetch(url_from_model)`. All of these are red flags.
- RAG retrieval calls (`similarity_search`, `.query(`, `vectorStore`): a tenant or user filter must be applied server-side.
- System prompts in code: no keys, internal hostnames or credentials.
- Retries, timeouts and fallbacks: is the provider client configured with `timeout` and `maxRetries`? Is there a fallback provider or a circuit breaker?
- Logging of prompts and responses: is it redacted, with a retention limit?

**Red flags:**

- `dangerouslyAllowBrowser: true`.
- Provider keys in `NEXT_PUBLIC_*` / `VITE_*`.
- An open proxy route that forwards any body to the provider.
- No per-user limit (a cost-exhaustion risk).
- Destructive tools (delete, refund, send email, payments) with no confirmation step.

## MCP servers and agent tools

**Good:**

- Remote MCP servers validate token audience: they accept only tokens issued to them and never pass client tokens through to downstream APIs.
- Proxies with a static OAuth client ID show their own per-client consent page.
- `redirect_uri` is matched exactly.
- `state` values are single-use and short-lived.
- Scopes are minimal with step-up when needed.
- URL fetches block private, loopback and link-local ranges (including `169.254.169.254`).
- Local servers use stdio, or HTTP with auth.

**Look for:**

- The token verification code: an `aud` / `resource` check.
- Any forwarding of the incoming `Authorization` header downstream.
- Wildcard scopes (`*`, `all`, `admin`).
- URL fetchers without SSRF protection.
- Tool descriptions that contain instructions aimed at the model.
- Third-party MCP servers in `.mcp.json` that are unpinned.

**Red flags:**

- Literal API keys in `.mcp.json`, `claude_desktop_config.json` or `mcp.json` `env` blocks. Use env references or a vault instead.
- Session or state handles treated as authentication.

## Payments

**Good:**

- Hosted fields or checkout, so card data never reaches your servers.
- Secret and restricted keys exist server-side only. Each service gets a restricted key with minimum permissions.
- Webhooks are verified on the raw body, deduplicated by event ID, and re-fetch the object before changing state.
- Amounts are computed on the server.
- Idempotency keys are set on every write.

**Look for:**

- Stripe: `stripe.webhooks.constructEvent(rawBody, sig, secret)` (Node), `stripe.Webhook.construct_event` (Python). The body must be raw: watch for `express.json()` or `bodyParser.json()` running before the webhook route, which breaks verification and tempts people to skip it.
- Razorpay: `validateWebhookSignature` / `utility.verify_webhook_signature`. For checkout, verify `razorpay_signature` on the server before marking an order paid.
- Adyen: HMAC validation of notifications (`hmacValidator.validateHMAC`).
- PayPal: the `verify-webhook-signature` API call.
- Price and amount: values like `amount: req.body.amount` or `price: body.price` are red flags. Look up the price by product ID on the server.
- Idempotency: `idempotencyKey` / `Idempotency-Key` on create, charge, refund and payout calls.
- The handler's response: return 2xx quickly and process asynchronously through a queue.
- Card data in logs: no logging of request bodies on payment routes.

**PCI script controls:** on pages that host the payment iframe or hosted fields, check for a CSP (enforced or report-only with a `report-to` endpoint), SRI on third-party scripts and a script inventory. The SAQ A eligibility condition depends on these.

**Red flags:**

- Live keys in the repo.
- Webhooks with no signature check.
- Order state changed by a client redirect, such as a `?success=true` page, rather than by the webhook.
- Test and live keys in the same config file.

## Analytics, error tracking and session replay

**Good:**

- Only write keys go to clients.
- Sensitive events are sent server-side.
- PII is scrubbed before events are sent.
- Replay masks inputs.
- Tags are gated on consent.
- Calls never block requests.

**Look for:**

- `identify(` / `capture(` / `track(` calls with `email`, `phone`, `name`, `address`, `token`, `password` or full URLs with query strings.
- Sentry: a `beforeSend` scrubber, `sendDefaultPii: false`, and request body / header / cookie scrubbing settings.
- PostHog, LogRocket, FullStory, Hotjar: input masking settings (`maskAllInputs`, `maskTextSelector`), with replay disabled on checkout, auth and settings routes.
- Read, export or admin API keys (PostHog personal API key, Mixpanel service account, Amplitude secret key, Segment access token) in client code or public env vars. These are red flags.
- Consent: tags load only after the consent manager allows them.
- `await` on analytics calls in the request path. Make them fire-and-forget or buffered.

## Auth providers and customer API keys

**Look for:**

- Supabase `service_role` keys, Firebase admin credentials, Auth0 client secrets or Clerk secret keys in client code or public env vars. These are red flags.
- JWT verification: algorithm pinned (no `none`, no `alg` taken from the token), and issuer and audience checked.
- Authorization: is every data query scoped by the session's user or tenant? Look for `findById(req.params.id)` without an owner check (IDOR).
- Customer-issued API keys: stored hashed (`sha256` / `argon2`), prefixed, scoped and expirable, and compared in constant time.
