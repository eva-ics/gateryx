<h2>
  gateryx - Lightweight WAF with built-in IDP
  <a href="https://crates.io/crates/gateryx"><img alt="crates.io page" src="https://img.shields.io/crates/v/gateryx.svg"></img></a>
  <a href="https://docs.rs/gateryx"><img alt="docs.rs page" src="https://docs.rs/gateryx/badge.svg"></img></a>
</h2>

<img src="https://raw.githubusercontent.com/eva-ics/gateryx/main/gateryx-logo.png"
width="100" />

[Gateryx](https://www.bohemia-automation.com/software/gateryx/) is a Web
Application Firewall (WAF) solution which delivers a fully integrated,
high-security web gateway by combining a next-generation reverse proxy and a
modern identity provider into a single, streamlined product. Built on fast,
battle-tested elliptic-curve cryptography (P-256), it provides passwordless
Passkey authentication, ES256-signed JWT and OIDC tokens, and ECDSA-secured
administrative access.

[Technical Documentation](https://info.bma.ai/en/actual/gateryx/index.html)

Key benefits
============

* Zero-Trust API Gateway. Enforce identity at the edge with ES256 JWT
  validation before traffic reaches web services.

* Passwordless Customer Login. Passkey/WebAuthn authentication for
  frictionless, phishing-resistant user access.

* Enterprise SSO & OIDC. A compact, integrated OIDC identity provider for
  internal tools, cloud apps, developer portals, and dashboards.

* Hardened Administrative Control Plane. Protect admin endpoints using RFC 9421
  ECDSA-signed requests - no passwords, no bearer tokens.

* High-Performance Edge Security Layer. Ultra-low latency ingress thanks to
  master–worker socketpairs and lightweight verification paths.

* Instant Deployment. Replace multiple tools (IdP, auth service, ingress, API
  gateway) with one product, one config, one rollout.

* Written purely in Rust: lightweight. blazing fast, tiny memory footprint,
  designed to run in embedded environments and resource-restricted virtual
  appliances.

AI coding policy
================

See [AICODE.md](AICODE.md).
