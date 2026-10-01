# Risks and acceptance

See [SECURITY.md](../SECURITY.md) for the threat model and residual risks,
[verification.md](verification.md) for current evidence, and
[operations.md](operations.md) for deployment duties.

Provider-side fetching occurs from the provider's network, so local VPN
exit guarantees do not extend to cloud scrape providers. Billing behavior,
provider storage rights and prices need operator review. Source labels do
not prevent indirect prompt injection or organization-specific data leakage.
