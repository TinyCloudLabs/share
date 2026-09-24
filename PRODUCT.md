# Product

## Users

An OpenKey-authenticated sender selects or uploads a file, chooses bearer or addressed access, and creates a revocable TinyCloud delegation. The sender's encrypted Vault keeps the canonical share record. A recipient opens the link, satisfies any recipient policy, and reads the encrypted content from the owner's TinyCloud node.

## Product purpose

TinyCloud Sharing demonstrates TinyCloud itself: content stays in the owner's TinyCloud space, access is delegated through TinyCloud, invocation is enforced by the owner's node, and revocation acts on the delegation rather than on a copied blob.

Bearer links are secret `/viewer#tc1=…` capabilities. Addressed/email links use `/s/inline#v=2&p=…`; the fragment contains a sealed signed policy envelope and its opening key, while access still requires proof of the matching identity. Email delivery is optional and occurs only after the owner node authorizes the exact recipient, resource, link, label, issuer/audience, short expiry, and single-use nonce.

There is no Share-host content database, R2/IPFS share blob store, capability registry, binding service, signing proxy, policy resolver, or content proxy. Pre-cutover links are not supported.

## Brand personality

Quietly technical, trustworthy, and humane. State security boundaries plainly and never imply that creating a link sent an email or that an email granted access.

## Design principles

- Make the owner's TinyCloud node visibly authoritative.
- Keep bearer and addressed invitation secrets in fragments and out of browser network requests.
- Keep addressed invitation material sealed in a fragment; content encryption remains the independent confidentiality boundary.
- Show exact resource, recipient, permissions, expiry, and revocation state.
- Make failed email delivery preserve the already-created share.
- Target WCAG 2.2 AA and keyboard-first, narrow-screen operation.
