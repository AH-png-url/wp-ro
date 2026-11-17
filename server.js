import http from "node:http";
import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import { URL, URLSearchParams } from "node:url";

const port = Number(process.env.PORT || 3000);
const maxResponseSize = Number(process.env.MAX_RESPONSE_SIZE || 25 * 1024 * 1024);
const allowedProtocols = new Set((process.env.ALLOWED_PROTOCOLS || "https:").split(",").map(v => v.trim()));

const allowedDomains = (process.env.ALLOWED_DOMAINS || "")
  .split(",").map(v => v.trim().toLower()).filter(Boolean);
const blockedDomains = (process.env.BLOCKED_DOMAINS || "")
  .split(",").map(v => v.trim().toLower()).filter(Boolean);

function domainMatches(hostname, domain) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const rule = domain.replace(/^\*\./, "").replace(/\.$/, "");
  return host === rule || host.endsWith(`.${rule}`);
}

function isPrivateIp(address) {
  const ipVersion = net.isIP(address);
  if (ipVersion === 4) {
    const parts = address.split(".").map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    if (parts[0] >= 224) return true;
  }
  if (ipVersion === 6) {
    const normalized = address.toLowerCase().split("%")[0];
    if (normalized === "::" || normalized === "::1") return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true;
    if (normalized.startsWith("::ffff:127." ) || normalized.startsWith("::ffff:10.")) return true;
  }
  return false;
}

async function validateUrl(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!allowedProtocols.has(url.protocol)) throw new Error("Protocol is not allowed");
  if (url.username || url.password) throw new Error("Userinfo is not allowed");

  const hostname = url.hostname.toLower.replace(/\.$/, "");
  if (blockedDomains.some(domain => domainMatches(hostname, domain))) {
    throw new Error("Domain is blocked");
  }
  if (allowedDomains.length && !allowedDomains.some(domain => domainMatches(hostname, domain))) {
    throw new Error("Domain is not in the allowlist");
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length) throw new Error("Hostname could not be resolved");
  if (records.some(({ address }) => isPrivateIp(address))) throw new Error("Private network access is blocked");

  return url;
}

function sanitizeUrl(url) {
  const trackingParams = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "msclkid"]);
  const params = new URLSearchParams(url.search);
  for (const key of [...params.keys()]) {
    if (trackingParams.has(key.toLowerCase())) params.delete(key);
  }
  url.search = params.toString();
}

function htmlEscape(value) {
  return value.replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[char]);
}

const indexHtml = `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Privacy Proxy</title>
<style>body{font:16px system-ui;max-width:760px;margin:8vh auto;padding:20px}form{display:flex;gap:.5rem}input{flex:1;padding:.8rem;font-size:1rem}button{padding:.8rem 1rem}small{color:#555}</style>
<h1>Privacy Proxy</h1>
<form action="/proxy" method="get"><input name="url" type="url" required placeholder="https://example.com"><button>Open</button></form>
<p><small>Only public, allowed domains are reachable. No request history is stored.</small></p></html>`;

function sendError(res, status, message) {
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  res.end(message);
}

async function proxyRequest(req, res) {
  let url;
  try {
    url = await validateUrl(req.url);
  } catch (error) {
    sendError(res, 400, error.message);
    return;
  }

  sanitizeUrl(url);
  const client = url.protocol === "https:" ? https : http;
  const request = client.request(url, {
    method: req.method,
    headers: {
      "accept": req.headers.accept || "*/*",
      "accept-language": "en",
      "user-agent": "PrivacyProxy/1.0",
      "if-modified-since": req.headers["if-modified-since"]
    },
    timeout: 15000
  }, upstream => {
    if (upstream.statusCode >= 300 && upstream.statusCode < 400 && upstream.headers.location) {
      try {
        const redirect = new URL(upstream.headers.location, url).toString();
        res.writeHead(302, { location: `/proxy?url=${encodeURIComponent(redirect)}`, "cache-control": "no-store" });
        upstream.resume();
        res.end();
      } catch {
        sendError(res, 502, "Invalid redirect");
      }
      return;
    }

    const allowedResponseHeaders = ["content-type", "content-length", "cache-control", "etag", "last-modified"];
    const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
    for (const name of allowedResponseHeaders) {
      if (upstream.headers[name]) headers[name] = upstream.headers[name];
    }
    if (Number(headers["content-length"] || 0) > maxResponseSize) {
      sendError(res, 413, "Response too large");
      upstream.resume();
      return;
    }
    res.writeHead(upstream.statusCode || 502, headers);

    let received = 0;
    upstream.on("data", chunk => {
      received += chunk.length;
      if (received > maxResponseSize) {
        upstream.destroy();
        if (!res.destroyed) sendError(res, 413, "Response too large");
      }
    });
    upstream.on("error", () => sendError(res, 502, "Upstream connection failed"));
    upstream.pipe(res);
  });

  request.on("error", () => sendError(res, 502, "Upstream connection failed"));
  request.on("timeout", () => request.destroy(new Error("Timeout")));
  req.pipe(request);
}

const server = http.createServer(async (req, res) => {
  const requestUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (requestUrl.pathname === "/" && req.method === "GET") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(indexHtml);
    return;
  }

  if (requestUrl.pathname === "/proxy" && req.method === "GET") {
    const target = requestUrl.searchParams.get("url");
    if (!target) {
      sendError(res, 400, "Missing url parameter");
      return;
    }
    await proxyRequest({ ...req, url: target, method: "GET" }, res);
    return;
  }

  sendError(res, 404, "Not found");
});

server.listen(port, () => {
  console.log(`Privacy proxy listening on port ${port}`);
});
