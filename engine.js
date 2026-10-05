(function (root) {
  'use strict';
  // DMARC record checker and identifier alignment, from RFC 7489 sections 3.1, 3.2, 6.3 and 6.4.
  var POLICIES = ['none', 'quarantine', 'reject'];
  var KNOWN = ['v', 'p', 'sp', 'rua', 'ruf', 'adkim', 'aspf', 'ri', 'fo', 'rf', 'pct'];
  var URI = /^([A-Za-z][A-Za-z0-9+.\-]*:[^\s,!;]*)(?:!(\d+)([kKmMgGtT]?))?$/;
  function issue(lvl, tag, msg) { return { lvl: lvl, tag: tag, msg: msg }; }
  function parse(input) {
    var raw = String(input), s = raw.trim(), issues = [], tags = [], i;
    if (/"/.test(s)) { s = s.replace(/"\s*"/g, '').replace(/"/g, ''); issues.push(issue('info', null, 'Quote marks were removed. A DNS tool often shows a long TXT record as several quoted pieces; the real record is the pieces joined without the quotes.')); }
    if (s === '') return { status: 'empty', issues: [issue('fatal', null, 'Paste the TXT record published at _dmarc.<your domain>.')], tags: [], strict: false, eff: null };
    var parts = s.split(';');
    if (parts.length && parts[parts.length - 1].trim() === '') parts.pop();
    var seen = {};
    parts.forEach(function (p, idx) {
      var t = p.trim();
      if (t === '') { issues.push(issue('syntax', null, 'Empty tag between two semicolons.')); return; }
      var eq = t.indexOf('=');
      if (eq < 0) { issues.push(issue('syntax', null, '"' + t + '" has no "=" so it is not a tag.')); tags.push({ name: t.toLowerCase(), value: '', bad: true }); return; }
      var name = t.slice(0, eq).trim().toLowerCase(), val = t.slice(eq + 1).trim();
      if (seen[name]) { issues.push(issue('syntax', name, 'The tag "' + name + '" appears twice. The grammar allows each tag once.')); }
      seen[name] = true; tags.push({ name: name, value: val, raw: t, idx: idx });
    });
    var first = tags[0];
    var status = 'valid';
    if (!first || first.name !== 'v') { issues.push(issue('fatal', 'v', 'The first tag must be v=DMARC1. Without it the whole record is ignored.')); status = 'ignored'; }
    else if (first.value !== 'DMARC1') {
      var why = first.value.toLowerCase().replace(/\s/g, '') === 'dmarc1' ? ' The value must be exactly DMARC1 in capital letters (RFC 7489 spells it with fixed hex codes, so lower case does not match).' : '';
      issues.push(issue('fatal', 'v', 'v must be exactly DMARC1, but it is "' + first.value + '". The whole record is ignored.' + why)); status = 'ignored';
    }
    var second = tags[1];
    var eff = { p: null, sp: null, pct: 100, adkim: 'r', aspf: 'r', ri: 86400, fo: ['0'], rf: ['afrf'], rua: [], ruf: [] };
    var pTag = tags.filter(function (t) { return t.name === 'p'; })[0];
    if (status !== 'ignored') {
      if (!pTag) issues.push(issue('error', 'p', 'The p tag is required for a policy record, and it is missing. This record states no policy.'));
      else if (!second || second.name !== 'p') issues.push(issue('error', 'p', 'The RFC says v and p must appear in that order, with p second. Here p comes later.'));
    }
    function policyTag(t) {
      var v = t.value.toLowerCase();
      if (POLICIES.indexOf(v) < 0) { issues.push(issue(t.name === 'p' ? 'error' : 'syntax', t.name, '"' + t.value + '" is not a policy. Use none, quarantine or reject.' + (t.value.indexOf(',') >= 0 || t.value.indexOf(' ') >= 0 ? ' Tags are separated by semicolons, not commas or spaces.' : ''))); return null; }
      return v;
    }
    function uriList(t) {
      var out = [];
      t.value.split(',').forEach(function (u) {
        u = u.trim(); var m = URI.exec(u);
        if (!m) { issues.push(issue('syntax', t.name, '"' + u + '" is not a valid URI. Use mailto:name@example.com.')); return; }
        var sch = u.split(':')[0].toLowerCase();
        if (sch !== 'mailto') issues.push(issue('warn', t.name, 'Receivers must support mailto: and may ignore other schemes such as ' + sch + ':.'));
        else if (!/^mailto:[^@\s]+@[^@\s,!]+$/i.test(m[1])) issues.push(issue('syntax', t.name, '"' + u + '" is not a mailto address.'));
        out.push(u);
      });
      return out;
    }
    if (status !== 'ignored') tags.forEach(function (t, k) {
      if (k === 0) return; if (t.bad) return;
      var v = t.value;
      switch (t.name) {
        case 'p': var pv = policyTag(t); if (pv) eff.p = pv; break;
        case 'sp': var sv = policyTag(t); if (sv) eff.sp = sv; break;
        case 'rua': eff.rua = uriList(t); break;
        case 'ruf': eff.ruf = uriList(t); break;
        case 'adkim': case 'aspf':
          if (/^[rsRS]$/.test(v)) eff[t.name] = v.toLowerCase(); else issues.push(issue('syntax', t.name, '"' + v + '" is not valid. Use r (relaxed) or s (strict). The default r is used.')); break;
        case 'ri':
          if (/^\d+$/.test(v) && +v <= 4294967295) eff.ri = +v; else issues.push(issue('syntax', 'ri', '"' + v + '" is not a 32-bit unsigned whole number of seconds. The default 86400 is used.')); break;
        case 'pct':
          if (/^\d{1,3}$/.test(v) && +v <= 100) eff.pct = +v;
          else issues.push(issue('syntax', 'pct', '"' + v + '" is not a whole number from 0 to 100' + (/%/.test(v) ? ' (drop the % sign)' : '') + '. The default 100 is used.'));
          break;
        case 'fo':
          if (/^[01ds]([ \t]*:[ \t]*[01ds])*$/i.test(v)) eff.fo = v.split(':').map(function (x) { return x.trim().toLowerCase(); });
          else issues.push(issue('syntax', 'fo', '"' + v + '" is not a colon-separated list of 0, 1, d and s. The default 0 is used.'));
          break;
        case 'rf':
          if (/^[A-Za-z0-9\-]+([ \t]*:[ \t]*[A-Za-z0-9\-]+)*$/.test(v)) eff.rf = v.split(':').map(function (x) { return x.trim().toLowerCase(); });
          else issues.push(issue('syntax', 'rf', '"' + v + '" is not a colon-separated list of report formats.'));
          break;
        case 'v': issues.push(issue('syntax', 'v', 'v appears again after the first tag.')); break;
        default: issues.push(issue('info', t.name, 'Unknown tag "' + t.name + '" is ignored by receivers.'));
      }
    });
    if (status !== 'ignored') {
      if (!pTag || eff.p === null) status = 'invalid';
      if (eff.ruf.length === 0 && tags.some(function (t) { return t.name === 'fo'; })) issues.push(issue('info', 'fo', 'fo is ignored because there is no ruf tag.'));
      if (eff.pct < 100 && eff.p && eff.p !== 'none') issues.push(issue('info', 'pct', 'Only ' + eff.pct + ' percent of failing mail gets the ' + eff.p + ' policy. The rest gets the next weaker one.'));
      if (eff.pct < 100 && eff.p === 'none') issues.push(issue('info', 'pct', 'pct has no effect with p=none.'));
    }
    var strict = !issues.some(function (x) { return x.lvl === 'fatal' || x.lvl === 'error' || x.lvl === 'syntax'; }) && status === 'valid';
    return { status: status, issues: issues, tags: tags, strict: strict, eff: eff };
  }
  var SUFFIX2 = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.il', 'org.il', 'ac.il', 'com.br', 'com.cn', 'com.tr', 'com.mx', 'com.ar', 'co.in', 'co.za', 'com.sg', 'com.hk'];
  function norm(d) { return String(d).trim().toLowerCase().replace(/\.$/, '').replace(/^.*@/, ''); }
  function orgDomain(d) {
    d = norm(d); var l = d.split('.');
    if (l.length <= 2) return d;
    if (SUFFIX2.indexOf(l.slice(-2).join('.')) >= 0) return l.slice(-3).join('.');
    return l.slice(-2).join('.');
  }
  function aligned(fromD, otherD, mode) {
    var a = norm(fromD), b = norm(otherD);
    if (!a || !b) return null;
    return mode === 's' ? a === b : orgDomain(a) === orgDomain(b);
  }
  var api = { parse: parse, orgDomain: orgDomain, aligned: aligned, norm: norm };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.DmarcWhy = api;
})(typeof window !== 'undefined' ? window : this);
