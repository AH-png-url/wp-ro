# Privacy-Focused Web Proxy

A small Node.js HTTP proxy that lets you open public web pages through a server-side allowlist.

## Features

- URL allowlist and denylist
- Blocks loopback, private, link-local, reserved, and other local networks
- Follows redirects while rechecking destination hosts
- Strips tracking-related query parameters
- Removes cookies and browser-identifying headers
- No request history or response-body logging
- Simple web interface

## Requirements

- Node.js 20 or newer

## Start

```bash
npm install
npm start
```

Open `http://localhost:3000`.

The default configuration allows HTTPS pages only. Set `ALLOWED_DOMAINS` to a comma-separated allowlist:

```bash
ALLOWED_DOMAINS="example.com,wikipedia.org" npm start
```

Set `BLOCKED_DOMAINS` for additional denied domains:

```bash
BLOCKED_DOMAINS="ads.example.com" npm start
```

## Deployment

Set `PORT`, `ALLOWED_PROTOCOLS`, `ALLOWED_DOMAINS`, `BLOCKED_DOMAINS`, and `MAX_RESPONSE_SIZE` as environment variables. Put the service behind HTTPS in production.

This proxy must only be used for content you are authorized to access. It cannot bypass authentication, DRM, paywalls, or terms of service.
