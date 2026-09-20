# Cindera

A cybersecurity digest — daily / weekly / monthly + breaking — behind **one
encrypted link** you pin in your WhatsApp group. It rebuilds itself on GitHub
Pages, so the pinned link is always current. Free, and fully within WhatsApp's
rules (you're just sharing a URL).

- **Encrypted:** AES-256-GCM, key from your passphrase. Published file is ciphertext
  only; a stranger with the URL sees a lock screen.
- **Auto-updating:** GitHub Actions rebuilds daily; the link never changes.
- **20 verified sources:** news, CISA advisories, CISA KEV (JSON), vendor/threat-intel,
  and healthcare-breach feeds. Severity-ranked so the important item leads. Dead feeds
  are skipped.
- **Grouped sections:** each Daily/Weekly/Monthly tab leads with the top threat, then
  splits into **CVE & Advisories**, **Threat Actor / Intel**, **Healthcare Breaches**
  and **Other News**, so no category crowds out the others.

## Quick start
1. Push to a GitHub repo (public is fine — no secrets are in it).
2. Add secret `PAGE_PASSPHRASE` (your group passphrase).
3. Settings → Pages → Source = GitHub Actions.
4. Run the workflow. Pin `https://<you>.github.io/<repo>/` in the group; share the
   passphrase separately.

Full walkthrough: **IMPLEMENTATION.md**.
