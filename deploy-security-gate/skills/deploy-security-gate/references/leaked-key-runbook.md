# Leaked-key runbook

The target is under 15 minutes from discovery to revocation. Revoke first and investigate after: a leaked key is used by bots within minutes of reaching a public repo or bundle.

A key counts as leaked if it was ever in:

- git history, even in a private repo, and even if it was deleted in a later commit
- a frontend or mobile bundle
- CI logs, a Docker image layer or a public package
- a chat, ticket or document
- a prompt or file read by a third-party AI tool

## Steps

1. **Revoke or disable at the provider.** Do this first. Confirm with the user before acting, because revoking breaks anything still using the key; a replacement may be needed at the same moment.
2. **Issue a replacement** through the secrets manager, scoped as narrowly as possible. Deployments should pick it up without a code change. If they can't, that is a separate finding: there's no runtime injection.
3. **Review the provider's usage logs** for the key's whole lifetime: calls made, data accessed, money spent, and any new keys, users or webhooks the attacker may have created for persistence.
4. **Remove the secret from where it leaked:**
   - code: delete it and use a vault lookup
   - history: `git filter-repo`, then force-push, and ask the git host to purge cached views
   - bundles: rebuild and purge the CDN
   - images: rebuild and delete the old tags
   - logs: delete them

   This step does not make the key safe again. Only step 1 does.
5. **Find the root cause and add a control:** a pre-commit hook, push protection, a CI bundle scan, a client-env prefix rule or an agent deny rule. Rerun `scripts/scan.py --history`.
6. **Notify** if data was exposed: affected customers and regulators within legal deadlines (72 hours under GDPR), plus the provider's security team if abuse continues.

## Where to revoke

| Provider | Where |
| --- | --- |
| AWS IAM access key | IAM console → Users → Security credentials → Deactivate, then Delete. Check CloudTrail for the key ID |
| GCP service-account key | IAM → Service accounts → Keys → Delete. Prefer workload identity federation instead of keys |
| Azure | Entra ID app registration → Certificates & secrets → Delete. Prefer managed identity |
| Anthropic | Console → API keys → Delete. Check usage per workspace |
| OpenAI | Platform → API keys → Revoke. Check usage per project |
| Google AI / Gemini / Maps | Cloud console → APIs & Services → Credentials → Delete or Regenerate; add restrictions |
| Stripe | Dashboard → Developers → API keys → Roll key (choose an expiry for the old key). For webhook secrets, roll the endpoint secret |
| Razorpay | Dashboard → Account & Settings → API keys → Regenerate. Change the webhook secret per webhook |
| GitHub token | Settings → Developer settings → Tokens → Delete. For org-wide exposure, review the audit log |
| npm | `npm token revoke <id>` or the website's token settings. Republish affected versions if a publish token was abused |
| Slack | Revoke the token, or regenerate the webhook URL |
| Database password | Rotate the credential in the secrets manager or DB, then restart the consumers. Check DB logs for unknown clients |
| Private key / TLS key | Revoke and reissue the certificate; rotate SSH keys and remove them from `authorized_keys` |

## Afterwards

- Record the incident: the key, how it was exposed, the exposure window, the actions taken and the new control.
- If the same type of leak happens twice, it is a process gap. Add an automated control, not a reminder.
