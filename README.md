
Threat intel toolkit that brings multiple sources together in one place. Paste an IP, domain, URL, hash, or CVE and get results from multiple integrated services simultaneously.
## Integrated Sources

| Source | Type | What it shows |
|--------|------|----------------|
| **VirusTotal** | IP, Domain, URL, Hash | Detection ratio, categories, permalink to GUI |
| **AbuseIPDB** | IP | Abuse score, ISP, country, usage type |
| **Shodan** | IP | Open ports, org, vulnerabilities, geolocation |
| **AlienVault OTX** | IP, Domain, URL | Threat pulses, malware families, adversaries |
| **URLScan.io** | URL, Domain | Screenshots, verdicts, technologies used |
| **WHOIS / RDAP** | IP, Domain | ASN, registrar, creation/expiry dates |
| **MalwareBazaar** | Hash | Signatures, tags, file info |
| **NVD / NIST** | CVE | CVSS scores, severity, references |
| **DNS Lookup** | Domain | A, AAAA, MX, TXT, NS records |

## Features
- **Live & Demo modes** - Toggle between real API data and mock responses
- **Direct permalinks** - One click to open results in the original source
- **Emoji service icons** - No external dependencies, works offline
- **Auto-detection** - Figures out if your input is an IP, domain, URL, hash, or CVE
- **Server-side API keys** - Keys stay in Cloudflare, never touch the browser

## Stack
- **Frontend:** Preact (lightweight React alternative)
- **Backend:** Cloudflare Pages Functions
- **Build:** esbuild (fast bundling)
- **Deploy:** Cloudflare Pages

## Quick Start

### 1. Clone & Install
```bash
git clone <repo-url>
cd AtlaSoc-ToolBox
npm install
```

### 2. Add API Keys
Create `.env` file:

```bash
VT_API_KEY=your_virustotal_key
ABUSEIPDB_KEY=your_abuseipdb_key
SHODAN_KEY=your_shodan_key      # optional
OTX_KEY=your_otx_key
URLSCAN_KEY=your_urlscan_key
MALWAREBAZAAR_KEY=your_malwarebazaar_key
NVD_API_KEY=your_nvd_key         # optional
```

Get free API keys:
- [VirusTotal](https://www.virustotal.com/gui/my-apikey)
- [AbuseIPDB](https://www.abuseipdb.com/account/api)
- [OTX AlienVault](https://otx.alienvault.com/settings)
- [URLScan](https://urlscan.io/user/settings/)
- [MalwareBazaar](https://bazaar.abuse.ch/api/)

### 3. Run Locally
```bash
npx wrangler pages dev . --port 8788
```

Open / visit :  `http://localhost:8788`

### 4. Deploy to Cloudflare Pages
```bash
npx wrangler pages deploy . --project-name=soc-atlasvec-com
```

Or upload directly via [Cloudflare Dashboard](https://dash.cloudflare.com/):
1. Create a project - Direct Upload
2. Upload the project folder
3. Build command: `npm run build`
4. Add environment variables from your `.env`

## Project Structure

```
AtlaSoc-ToolBox/
├── src/main.jsx             # Frontend (Preact)
├── functions/api/
│   └── [[route]].js         # Backend API handlers
├── main.js                  # Built frontend (208.6kb)
├── _headers                 # Security headers
├── package.json             # Dependencies
├── .env.example             # API key template
└── README.md                # This file
```

## Known Limitations

- Shodan requires API key for IP intelligence
- Some services have rate limits (handled by Cloudflare)
- Hash lookups work best with SHA-256

## Contributing

This is a personal toolkit that evolves with my workflow. If you spot a bug or have an idea, open an issue or PR.

## License
MIT

---
Built for practical threat hunting and CTF investigations.