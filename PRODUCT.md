# Product

## Register

product

## Users

TinyCloud users sharing a file or folder, recipients opening a share in a browser for the first time or on a returning device, and personal agents acting for either party. Senders are usually already authenticated; recipients may have no TinyCloud account or vocabulary. Their job is to share or open the intended content quickly while retaining cryptographic confidence about who sent it, who may open it, and what access was granted.

## Product Purpose

TinyCloud Sharing turns an encrypted link into a trustworthy handoff. The link transports a sender-authenticated, least-privilege delegation while the recipient proves the named identity or key locally. Success means an existing user can share with one confirmation, a new recipient can reach content without learning protocol concepts, and bearer links remain available with their weaker security stated plainly.

## Brand Personality

Calm, trustworthy, and direct. The interface should make unfamiliar cryptographic work feel ordinary without concealing meaningful security differences. It should feel like opening a well-addressed document, not joining a new platform.

## Anti-references

- Signup funnels, dashboards, plan pickers, or product tours inserted between the recipient and shared content.
- Security theater: lock decoration, vague claims, or jargon such as DID, UCAN, delegation, policy, and VP in the primary flow.
- Phishing-shaped pages that ask for a passkey or email proof before establishing the verified sender, filename, and intended recipient.
- Decorative SaaS styling, gratuitous motion, third-party analytics, and any visual treatment that competes with the document.
- Silent ambiguity about bearer-link authority, wrong-account failures, expiry, or read/write scope.

## Design Principles

1. Establish trust before asking for identity: verify locally, then show the sender, content name, recipient, scope, and expiry before any ceremony.
2. Keep plumbing automatic: the only human decisions are identity, consent, and recipient correctness.
3. Make the content the destination: authentication and claiming are a short inline path, never a separate onboarding product.
4. State security differences plainly: addressed, recipient-DID, and bearer shares must never look equivalent when their theft and revocation properties differ.
5. Fail closed without becoming mysterious: preserve privacy, name the corrective action, and never contact an unverified node or identity provider.

## Accessibility & Inclusion

Target WCAG 2.2 AA for the browser flow. All actions must be keyboard reachable with visible focus, status and errors must be announced without relying on color, and text must remain legible at zoom and narrow widths. Respect reduced-motion and system color-scheme preferences. Passkey, wrong-account, expired-link, and verification failures need plain-language alternatives that do not assume protocol knowledge.
