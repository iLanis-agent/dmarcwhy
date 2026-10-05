// No third-party DMARC checker is available offline, so this compares engine.js with an independent
// transcription of the RFC 7489 section 6.4 ABNF (as per-tag regexes) on generated and mutated records,
// and checks the alignment examples quoted in RFC 7489 section 3.1 and the organizational-domain rule of 3.2.
const g = require('./engine.js'); let seed = +process.env.SEED || 3; const rnd = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296; const pick = a => a[Math.floor(rnd() * a.length)];
const ci = s => s.replace(/[a-z]/gi, c => '[' + c.toLowerCase() + c.toUpperCase() + ']');
const W = '[ \\t]*', URIX = '[A-Za-z][A-Za-z0-9+.\\-]*:[^\\s,!;]+(?:!\\d+[kKmMgGtT]?)?';
const TAG = {
  p: new RegExp('^' + ci('p') + W + '=' + W + '(' + ci('none') + '|' + ci('quarantine') + '|' + ci('reject') + ')$'),
  sp: new RegExp('^' + ci('sp') + W + '=' + W + '(' + ci('none') + '|' + ci('quarantine') + '|' + ci('reject') + ')$'),
  rua: new RegExp('^' + ci('rua') + W + '=' + W + URIX + '(' + W + ',' + W + URIX + ')*$'),
  ruf: new RegExp('^' + ci('ruf') + W + '=' + W + URIX + '(' + W + ',' + W + URIX + ')*$'),
  adkim: new RegExp('^' + ci('adkim') + W + '=' + W + '[rsRS]$'), aspf: new RegExp('^' + ci('aspf') + W + '=' + W + '[rsRS]$'),
  ri: /^[rR][iI][ \t]*=[ \t]*\d+$/, fo: new RegExp('^' + ci('fo') + W + '=' + W + '[01dsDS](' + W + ':' + W + '[01dsDS])*$'),
  rf: new RegExp('^' + ci('rf') + W + '=' + W + '[A-Za-z0-9\\-]+(' + W + ':' + W + '[A-Za-z0-9\\-]+)*$'), pct: /^[pP][cC][tT][ \t]*=[ \t]*\d{1,3}$/
};
const V = /^[vV][ \t]*=[ \t]*DMARC1$/;
function abnfValid(rec) {
  let parts = rec.split(';'); if (parts.length && parts[parts.length - 1].trim() === '') parts.pop();
  parts = parts.map(x => x.trim()); if (parts.some(x => x === '')) return false;
  if (!parts[0] || !V.test(parts[0])) return false;
  if (!parts[1] || !TAG.p.test(parts[1])) return false;
  const seen = new Set();
  for (const p of parts.slice(2)) {
    const name = (/^([A-Za-z]+)/.exec(p) || [])[1]; if (!name) return false; const n = name.toLowerCase();
    if (!TAG[n] || n === 'p' || seen.has(n)) return false; seen.add(n);
    if (!TAG[n].test(p)) return false;
    if (n === 'pct' && +p.split('=')[1] > 100) return false; // 1*3DIGIT in the grammar, 0..100 in the prose of 6.3
    if (n === 'ri' && +p.split('=')[1] > 4294967295) return false;
  }
  return true;
}
const VALUES = { p: ['none', 'quarantine', 'reject', 'REJECT', 'Quarantine', 'block', 'none,', ''], sp: ['none', 'reject', 'quarantine', 'x'], rua: ['mailto:a@example.com', 'mailto:a@example.com,mailto:b@example.org', 'a@example.com', 'mailto:a@example.com!10m', 'https://example.com/r', 'mailto:'], ruf: ['mailto:f@example.com', 'f@example.com'], adkim: ['r', 's', 'R', 'x', 'strict'], aspf: ['r', 's', 'S', 'relaxed'], ri: ['86400', '3600', '1d', '99999999999', '0'], fo: ['0', '1', 'd', 's', '0:1:d:s', '0:x', '1,d', 'all'], rf: ['afrf', 'afrf:iodef', 'a b'], pct: ['100', '50', '0', '1000', '150', '50%', '5.5', '-1', '101', '99'] };
function genRecord() {
  const parts = ['v=' + (rnd() < 0.9 ? 'DMARC1' : pick(['dmarc1', 'DMARC2', 'DMARC 1']))], names = Object.keys(VALUES);
  if (rnd() < 0.95) parts.push('p=' + (rnd() < 0.85 ? pick(VALUES.p.slice(0, 3)) : pick(VALUES.p)));
  const rest = names.filter(n => n !== 'p' && rnd() < 0.4); for (let i = rest.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [rest[i], rest[j]] = [rest[j], rest[i]]; }
  rest.forEach(n => parts.push(n + pick(['=', ' = ', '=', '= ']) + (rnd() < 0.85 ? pick(VALUES[n].slice(0, 2)) : pick(VALUES[n]))));
  if (rnd() < 0.03) parts.push(pick(parts));
  if (rnd() < 0.03) parts.splice(1, 0, parts.pop());
  const sep = rnd() < 0.97 ? pick(['; ', ';', ' ; ']) : pick([', ', ' ']);
  return parts.join(sep) + pick(['', ';', '; ', ' ;']);
}
let n = 0, bad = [], valid = 0;
for (let i = 0; i < (+process.env.N || 30000); i++) {
  const r = genRecord(), want = abnfValid(r), got = g.parse(r).strict; n++; if (want) valid++;
  if (want !== got) bad.push({ r, want, got, issues: g.parse(r).issues.map(x => x.lvl + ':' + x.msg).slice(0, 3) });
}
// RFC 7489 section 3.1 / 3.2 quoted cases
const rfc = [
  ['SPF relaxed cbg.bounces.example.com vs example.com', g.aligned('example.com', 'cbg.bounces.example.com', 'r') === true],
  ['SPF strict cbg.bounces.example.com vs example.com', g.aligned('example.com', 'cbg.bounces.example.com', 's') === false],
  ['org domain of a.b.c.d.example.com', g.orgDomain('a.b.c.d.example.com') === 'example.com'],
  ['org domain of example.co.uk subdomain', g.orgDomain('mail.example.co.uk') === 'example.co.uk'],
  ['strict exact match is case-insensitive', g.aligned('Example.com', 'example.COM', 's') === true],
];
let rfcBad = rfc.filter(x => !x[1]).map(x => x[0]);
console.log(JSON.stringify({ records: n, rfcValid: valid, rfcInvalid: n - valid, mismatches: bad.length, rfcCases: rfc.length, rfcCaseFailures: rfcBad.length }));
bad.slice(0, 12).forEach(b => console.log(JSON.stringify(b))); rfcBad.forEach(x => console.log('RFC FAIL', x));
process.exit(bad.length || rfcBad.length ? 1 : 0);
