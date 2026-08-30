// ─── User-Agent parser ────────────────────────────────────────────────────
// Dependency-free, regex-based. Not exhaustive — covers the browsers, OSes
// and bots analysts actually see in proxy/access logs.

const BOTS = [
  [/googlebot/i, 'Googlebot'],
  [/bingbot/i, 'Bingbot'],
  [/slurp/i, 'Yahoo Slurp'],
  [/duckduckbot/i, 'DuckDuckBot'],
  [/baiduspider/i, 'Baiduspider'],
  [/yandexbot/i, 'YandexBot'],
  [/curl\//i, 'curl'],
  [/wget\//i, 'Wget'],
  [/python-requests/i, 'python-requests'],
  [/python-urllib/i, 'python-urllib'],
  [/go-http-client/i, 'Go-http-client'],
  [/java\//i, 'Java'],
  [/scrapy/i, 'Scrapy'],
  [/nmap/i, 'Nmap'],
  [/masscan/i, 'Masscan'],
  [/zgrab/i, 'ZGrab'],
  [/nikto/i, 'Nikto'],
  [/sqlmap/i, 'sqlmap'],
  [/bot|spider|crawler/i, 'Generic bot/crawler'],
];

const BROWSERS = [
  [/edg\/([\d.]+)/i, 'Edge'],
  [/opr\/([\d.]+)/i, 'Opera'],
  [/chrome\/([\d.]+)/i, 'Chrome'],
  [/crios\/([\d.]+)/i, 'Chrome (iOS)'],
  [/fxios\/([\d.]+)/i, 'Firefox (iOS)'],
  [/firefox\/([\d.]+)/i, 'Firefox'],
  [/version\/([\d.]+).*safari/i, 'Safari'],
  [/msie ([\d.]+)/i, 'Internet Explorer'],
  [/trident\/.*rv:([\d.]+)/i, 'Internet Explorer'],
];

const OS_LIST = [
  [/windows nt 10\.0/i, 'Windows', '10/11'],
  [/windows nt 6\.3/i, 'Windows', '8.1'],
  [/windows nt 6\.2/i, 'Windows', '8'],
  [/windows nt 6\.1/i, 'Windows', '7'],
  [/windows nt ([\d.]+)/i, 'Windows', null],
  [/mac os x ([\d_]+)/i, 'macOS', null],
  [/android ([\d.]+)/i, 'Android', null],
  [/iphone os ([\d_]+)/i, 'iOS', null],
  [/ipad.*os ([\d_]+)/i, 'iPadOS', null],
  [/cros /i, 'ChromeOS', null],
  [/linux/i, 'Linux', null],
];

// CPU architecture / bitness tokens, checked in priority order (Windows'
// Win64/WOW64 tokens take precedence over a bare "x86" substring match).
const ARCHITECTURES = [
  [/win64|wow64|x86_64|amd64/i, 'x64'],
  [/arm64|aarch64/i, 'ARM64'],
  [/armv\d/i, 'ARM'],
  [/i686|i386|x86(?!_64)/i, 'x86'],
];

// In-app / embedded browser (webview) tokens — these look like generic
// mobile browsers otherwise, but analysts care whether traffic came from
// an in-app webview vs. the real browser.
const EMBEDDED_APPS = [
  [/fban\/|fbav\//i, 'Facebook'],
  [/instagram/i, 'Instagram'],
  [/micromessenger/i, 'WeChat'],
  [/\bline\//i, 'Line'],
  [/\bdiscord\b/i, 'Discord'],
  [/musical_ly|tiktok/i, 'TikTok'],
  [/twitter/i, 'Twitter/X'],
  [/snapchat/i, 'Snapchat'],
  [/whatsapp/i, 'WhatsApp'],
];

const AUTOMATION_RE = /headlesschrome|phantomjs|selenium|puppeteer|playwright/i;

function detectArchitecture(raw) {
  for (const [pattern, name] of ARCHITECTURES) if (pattern.test(raw)) return name;
  return null;
}

function detectEmbeddedApp(raw) {
  for (const [pattern, name] of EMBEDDED_APPS) if (pattern.test(raw)) return name;
  return null;
}

export function parseUserAgent(ua) {
  const raw = (ua || '').trim();
  if (!raw) return null;

  const architecture = detectArchitecture(raw);
  const isAutomated = AUTOMATION_RE.test(raw);

  for (const [pattern, name] of BOTS) {
    if (pattern.test(raw)) {
      return {
        raw,
        isBot: true,
        botName: name,
        browser: null,
        browserVersion: null,
        engine: null,
        os: null,
        osVersion: null,
        deviceType: 'bot',
        architecture,
        embeddedApp: null,
        isAutomated,
      };
    }
  }

  let browser = null, browserVersion = null;
  for (const [pattern, name] of BROWSERS) {
    const m = raw.match(pattern);
    if (m) { browser = name; browserVersion = m[1] || null; break; }
  }

  let os = null, osVersion = null;
  for (const [pattern, name, fixedVersion] of OS_LIST) {
    const m = raw.match(pattern);
    if (m) {
      os = name;
      osVersion = fixedVersion || (m[1] ? m[1].replace(/_/g, '.') : null);
      break;
    }
  }

  const engine = /gecko\//i.test(raw) && /firefox/i.test(raw) ? 'Gecko'
    : /applewebkit/i.test(raw) ? (/chrome|edg|opr/i.test(raw) ? 'Blink' : 'WebKit')
    : /trident/i.test(raw) ? 'Trident'
    : null;

  const deviceType = /ipad|tablet/i.test(raw) ? 'tablet'
    : /mobile|iphone|android/i.test(raw) ? 'mobile'
    : 'desktop';

  const embeddedApp = detectEmbeddedApp(raw);

  return {
    raw,
    isBot: false,
    botName: null,
    browser,
    browserVersion,
    engine,
    os,
    osVersion,
    deviceType,
    architecture,
    embeddedApp,
    isAutomated,
  };
}
