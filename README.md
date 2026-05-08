
# AtlaSoc ToolBox

Part of my vibe coding series. I’ve been using various AI agents to handle coding, scripting, and security automation tasks. I built this tool during Threat Hunting CTFs because I needed something I could keep improving as my workflow changed. 

There are other tools out there, but I wanted something tailored to how I work. It helps me stay organized during CTFs and investigations. I avoid losing track of which indicators I’d checked across a bunch of open tabs. 

This kit puts everything in one place. Just paste an IP, domain, hash, or filename, and it queries all sources at once. It’s made my investigation workflow way faster, especially during timed events.
### Integrated Tools

- VirusTotal
- AbuseIPDB
- Shodan
- AlienVault OTX
- URLScan.io
- WHOIS / RDAP
- MalwareBazaar
- NVD / NIST CVE

### **What I Learned** 

First real project with Cloudflare Pages and serverless functions. Learned how to use Cloudflare KV for rate limiting and caching without a traditional server. Keeping API keys server-side in a serverless setup was a good security exercise. Got more comfortable with React and Preact, figuring out indicator type detection and routing. Working with 8 different APIs taught me how to handle async requests and manage rate limits across multiple services.
## How it works

The frontend is React/Preact (`src/main.jsx`). It detects the indicator type and figures out which sources support it.

Calls go to the backend on Cloudflare Pages (`functions/api/`). API keys stay server-side, so they never touch the browser. The backend also handles rate limiting and caching using Cloudflare KV.

If the backend isn't configured, the frontend falls back to mock data so the UI still works for demos.
## Stack

- Frontend: React / Preact
- Backend: Cloudflare Pages Functions
- Cache/Rate Limit: Cloudflare KV

## Future plans

I'm still fixing bugs and improving the tool. I want to add more sources, maybe MISP or internal SIEM feeds. I'm also looking at a simple timeline view for an IP to see how reports change over time. Automation is the top priority. Right now it's manual paste, but hooking it into a Discord bot or a Splunk alert action would make it way more useful during live hunting.
## Running it yourself

1. Clone the repo.
2. Set up the API keys as Cloudflare Pages environment variables. Check `functions/api/[[route]].js` for the list: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, etc.
3. Deploy to Cloudflare Pages or run locally with `wrangler`.

---
