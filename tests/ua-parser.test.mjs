// Regression tests for the User-Agent parser (src/lib/utilities/uaParser.js).
// Run with: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseUserAgent } from '../src/lib/utilities/uaParser.js';

test('returns null for empty input', () => {
  assert.equal(parseUserAgent(''), null);
  assert.equal(parseUserAgent('   '), null);
});

test('parses a desktop Chrome / Windows UA', () => {
  const r = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  assert.equal(r.isBot, false);
  assert.equal(r.browser, 'Chrome');
  assert.equal(r.browserVersion, '120.0.0.0');
  assert.equal(r.os, 'Windows');
  assert.equal(r.osVersion, '10/11');
  assert.equal(r.engine, 'Blink');
  assert.equal(r.deviceType, 'desktop');
});

test('parses a mobile Safari / iOS UA', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1');
  assert.equal(r.browser, 'Safari');
  assert.equal(r.os, 'iOS');
  assert.equal(r.osVersion, '17.4');
  assert.equal(r.deviceType, 'mobile');
});

test('parses Firefox / Linux UA', () => {
  const r = parseUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0');
  assert.equal(r.browser, 'Firefox');
  assert.equal(r.os, 'Linux');
  assert.equal(r.engine, 'Gecko');
});

test('detects Googlebot as a bot, not a browser', () => {
  const r = parseUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
  assert.equal(r.isBot, true);
  assert.equal(r.botName, 'Googlebot');
  assert.equal(r.deviceType, 'bot');
});

test('detects curl as a bot', () => {
  const r = parseUserAgent('curl/8.4.0');
  assert.equal(r.isBot, true);
  assert.equal(r.botName, 'curl');
});

test('detects x64 architecture on a Windows UA', () => {
  const r = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  assert.equal(r.architecture, 'x64');
});

test('detects ARM64 architecture on a macOS UA', () => {
  const r = parseUserAgent('Mozilla/5.0 (Macintosh; ARM64 Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15');
  assert.equal(r.architecture, 'ARM64');
});

test('returns null architecture when the UA carries no CPU token', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1');
  assert.equal(r.architecture, null);
});

test('flags the Facebook in-app browser as an embedded app', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/460.0.0]');
  assert.equal(r.embeddedApp, 'Facebook');
});

test('leaves embeddedApp null for a normal browser UA', () => {
  const r = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  assert.equal(r.embeddedApp, null);
});

test('flags HeadlessChrome as automated without reclassifying it as a bot', () => {
  const r = parseUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36');
  assert.equal(r.isAutomated, true);
  assert.equal(r.isBot, false);
  assert.equal(r.browser, 'Chrome');
});

test('leaves isAutomated false for a normal browser UA', () => {
  const r = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  assert.equal(r.isAutomated, false);
});
