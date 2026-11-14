/* ScamShield v1: transparent, local-only heuristic checks. No network calls. */
(() => {
  'use strict';

  const RULES = [
    { id: 'urgency', title: 'Pressure to act immediately', level: 'medium', weight: 18, pattern: /\b(?:act now|immediately|urgent(?:ly)?|within (?:\d+|\w+) (?:hours?|minutes?)|expires? today|last chance|final notice|right away|don't delay|do not delay|limited time)\b/i, why: 'Scammers create a rush so you have less time to check whether a request is real.', action: 'Pause. Verify the request through an official contact method you find yourself.' },
    { id: 'threat', title: 'Threat or account warning', level: 'high', weight: 25, pattern: /\b(?:account (?:will be|has been|is being) (?:suspended|blocked|closed|locked)|suspend(?:ed|ing)? (?:your )?account|account (?:safety|security) alert|legal action|warrant|arrest(?:ed)?|penalty|service (?:will be )?disconnected)\b/i, why: 'A frightening warning can push you to click a link or share details before checking with the organization.', action: 'Open the official app or call a number from your card or a statement. Do not use the message link.' },
    { id: 'prize', title: 'Prize or lottery claim', level: 'high', weight: 28, pattern: /\b(?:you(?:'ve| have) (?:won|been selected)|congratulations.{0,30}(?:won|winner|prize)|lottery|sweepstakes|claim (?:your )?(?:prize|reward|winnings)|prize money|lucky winner)\b/i, why: 'Unexpected prizes are often used to collect a fee or personal information. Real prizes do not require you to pay to receive them.', action: 'Do not pay a fee or provide personal details to claim an unexpected prize.' },
    { id: 'credentials', title: 'Request for a secret or login detail', level: 'high', weight: 30, pattern: /\b(?:otp|one[ -]time (?:password|passcode)|verification code|password|upi pin|pin number|cvv|security code|banking details|card details|login credentials)\b/i, why: 'One-time codes, PINs, passwords, and card security details can let someone access your account. Legitimate support staff should not ask you to disclose them.', action: 'Never share a one-time code, PIN, password, or card security code. Contact your bank through its official app or number.' },
    { id: 'payment', title: 'Unusual payment request', level: 'high', weight: 27, pattern: /\b(?:pay (?:a )?(?:small )?(?:fee|charge|tax|deposit)|send (?:money|payment|funds)|wire (?:the )?money|gift cards?|crypto(?:currency)?|bitcoin|pay via (?:upi|wallet|transfer)|processing fee|refundable fee|payment required)\b/i, why: 'Scammers often ask for hard-to-reverse payment, gift cards, cryptocurrency, or a made-up release fee.', action: 'Do not send money or gift card codes. Verify the payment request independently.' },
    { id: 'impersonation', title: 'Possible organization impersonation', level: 'medium', weight: 16, pattern: /\b(?:dear (?:customer|user|account holder)|(?:your )?(?:bank|paypal|amazon|netflix|microsoft|apple|government|tax department) (?:account|profile)|on behalf of (?:your )?(?:bank|government)|customer support team)\b/i, why: 'A familiar organization name is easy to copy. This wording alone does not prove who sent the message.', action: 'Check the request in the official app or contact the organization using details from its known website.' },
    { id: 'remote-access', title: 'Request to install an app or allow remote access', level: 'high', weight: 28, pattern: /\b(?:install (?:this|the) app|download (?:this|the) app|screen.?sharing|remote access|remote control|anydesk|teamviewer|quick.?support|grant (?:us )?access to your (?:phone|device|screen))\b/i, why: 'Remote access can let another person view your screen, use apps, and approve transactions as you.', action: 'Do not install remote access software or share your screen with an unsolicited caller or sender.' },
    { id: 'shortener', title: 'Shortened link', level: 'medium', weight: 17, pattern: /(?:https?:\/\/)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|rebrand\.ly|ow\.ly|buff\.ly)\b/i, why: 'A short link hides the destination, so it is harder to tell where it goes before opening it.', action: 'Avoid opening a link you were not expecting. Visit the organization’s site by typing its address yourself.' },
    { id: 'authority', title: 'Claim of official authority', level: 'medium', weight: 14, pattern: /\b(?:police|customs|tax authority|income tax|government agency|court|immigration)\b.{0,70}\b(?:pay|fine|verify|arrest|penalty|urgent|suspended|case)\b/i, why: 'Scammers may invoke an authority or penalty to intimidate you into paying or responding quickly.', action: 'Find the agency’s official contact details independently before responding or paying.' }
  ];
  const SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','rb.gy','shorturl.at','rebrand.ly','ow.ly','buff.ly','goo.gl','lnkd.in']);
  const SAMPLE = 'ALERT: Your bank account will be suspended today. Verify immediately at http://bit.ly/secure-check and reply with your OTP to avoid losing access.';
  const $ = (id) => document.getElementById(id);

  function extractUrls(text) {
    const matches = text.match(/(?:https?:\/\/|www\.)[^\s<>{}\[\]"']+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?:\/[^\s<>{}\[\]"']*)?/gi) || [];
    const clean = matches.map(value => value.replace(/[),.!?;:]+$/g, '')).filter(Boolean);
    return [...new Set(clean)].slice(0, 20);
  }

  function parseUrl(raw) {
    let candidate = raw.trim();
    if (!candidate) throw new Error('Enter a web address to check.');
    if (/^[a-z]+:/i.test(candidate) && !/^https?:\/\//i.test(candidate)) throw new Error('Only web addresses that start with http:// or https:// can be checked.');
    if (!/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`;
    let parsed;
    try { parsed = new URL(candidate); } catch { throw new Error('That address doesn’t look complete. Check it and try again.'); }
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error('Enter a complete http or https web address.');
    return parsed;
  }

  function analyzeUrl(raw) {
    const url = parseUrl(raw);
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const findings = [];
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const ipv6 = host.includes(':');
    if (ipv4 || ipv6) findings.push({id:'ip-host', title:'Address uses an IP number', level:'high', weight:30, why:'A numeric address instead of a recognizable domain can be used to disguise where a link leads.', action:'Do not sign in or enter payment details on this page.'});
    if (url.username || url.password || raw.includes('@')) findings.push({id:'at-sign', title:'An @ symbol or embedded login appears in the address', level:'high', weight:28, why:'Text before an @ sign can make a deceptive address look like it belongs to a trusted site. The actual destination is after the @.', action:'Do not open the link. Find the organization’s site independently.'});
    const labels = host.split('.');
    if (labels.length >= 5) findings.push({id:'subdomains', title:'Many subdomain levels', level:'medium', weight:16, why:'Several domain levels can make the meaningful site name harder to spot.', action:'Read the domain from right to left and check the registered name carefully.'});
    if (SHORTENERS.has(host)) findings.push({id:'shortener', title:'Known URL shortener', level:'medium', weight:17, why:'The short link hides its final destination from you.', action:'Avoid opening unexpected short links.'});
    if (host.includes('xn--')) findings.push({id:'punycode', title:'Encoded domain name', level:'medium', weight:20, why:'Some international characters are encoded in a way that can make a lookalike domain difficult to notice.', action:'Use a bookmark or type the organization’s known address yourself.'});
    if (labels.some(label => label.length > 35)) findings.push({id:'long-label', title:'Unusually long domain section', level:'low', weight:10, why:'An extra-long domain label can obscure the part of the address that identifies the site.', action:'Check the registered domain before entering any information.'});
    const suspiciousParams = [...url.searchParams.keys()].filter(key => /(?:redirect|return|continue|next|url|target|dest|token|session|auth|verify|login|account)/i.test(key));
    if (suspiciousParams.length) findings.push({id:'params', title:'Sensitive or redirect-style URL parameters', level:'medium', weight:14, why:`The address includes parameter names such as ${suspiciousParams.slice(0,3).join(', ')}. These can carry a redirect or account flow, but are not proof of malicious activity.`, action:'Avoid entering credentials after following an unexpected link.'});
    if (url.protocol === 'http:') findings.push({id:'http', title:'Connection does not use HTTPS', level:'low', weight:10, why:'HTTP does not protect information sent to the site in transit.', action:'Do not submit sensitive information on an HTTP page.'});
    const score = Math.min(100, findings.reduce((sum, f) => sum + f.weight, 0));
    return {url, findings, score};
  }

  function scoreLabel(score) {
    if (score >= 55) return {heading:'Several strong warning signs', category:'High risk indicators detected', color:'#bd4c3c', summary:'This content contains several warning signs. Treat it with care and verify through a trusted channel.'};
    if (score >= 25) return {heading:'Some warning signs found', category:'Medium risk indicators detected', color:'#c1832d', summary:'A few details deserve a closer look. Verify the sender and request before taking action.'};
    return {heading:'Few warning signs found', category:'Low risk indicators detected', color:'#4a9a70', summary:'We found few common warning signs. That does not prove the message or link is safe.'};
  }

  function analyzeMessage(text) {
    const urls = extractUrls(text);
    const findings = RULES.filter(rule => rule.pattern.test(text)).map(rule => {
      const match = text.match(rule.pattern);
      return {...rule, phrase: match ? match[0] : ''};
    });
    for (const raw of urls) {
      try {
        const result = analyzeUrl(raw);
        for (const urlFinding of result.findings) {
          const sameIndicator = findings.some(f => f.id === urlFinding.id || (urlFinding.id === 'shortener' && f.id === 'shortener'));
          if (!sameIndicator && !findings.some(f => f.id === `url-${urlFinding.id}`)) findings.push({...urlFinding, id:`url-${urlFinding.id}`, title:`Link: ${urlFinding.title}`, phrase:raw});
        }
      } catch { /* Malformed text fragments are shown as extracted, not treated as visited. */ }
    }
    const score = Math.min(100, findings.reduce((sum, item) => sum + item.weight, 0));
    const seenHigh = findings.some(f => f.level === 'high');
    let next = 'If you’re unsure, contact the person or organization using a number or website you find independently. Do not reply to this message or use its links to verify it.';
    if (findings.some(f => f.id === 'credentials')) next = 'Do not share any code, PIN, or password. If you already shared one, contact your bank or service provider using its official app or number as soon as possible.';
    else if (findings.some(f => f.id === 'payment')) next = 'Do not send money or codes. Independently look up the organization and ask whether the request is real.';
    else if (findings.some(f => f.id === 'remote-access')) next = 'Do not install the app or share your screen. If you already granted access, disconnect from the internet and contact your bank using its official number.';
    else if (findings.some(f => f.id === 'threat')) next = 'Do not use the message link. Check your account by opening the official app or calling a number you already trust.';
    if (!findings.length && !urls.length) next = 'No common warning signs were found. Still, verify unexpected requests independently and never share passwords, PINs, or one-time codes.';
    else if (!findings.length && urls.length && !seenHigh) next = 'No common message warning signs were found, but the links have not been reputation-checked. Only open a link you expected and can verify.';
    return {findings, urls, score, label:scoreLabel(score), next};
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function findingCard(finding) {
    const card = el('article','finding'); card.dataset.level = finding.level;
    const head = el('div','finding-head');
    head.append(el('span','finding-bullet', finding.level === 'high' ? '!' : finding.level === 'medium' ? '·' : 'i'));
    const copy = el('div'); copy.append(el('h4','',finding.title),el('p','',finding.why),el('p','user-action',`What to do: ${finding.action}`));
    if (finding.phrase) copy.append(el('span','highlighted-phrase',`“${finding.phrase}”`));
    head.append(copy);card.append(head);return card;
  }

  function renderMessage(text) {
    const result = analyzeMessage(text);
    const info = result.label;
    $('risk-score').textContent = String(result.score);
    $('risk-heading').textContent = info.heading;
    $('risk-summary').textContent = info.summary;
    $('assessment-kicker').textContent = info.category.toUpperCase();
    $('score-ring').style.setProperty('--score-angle', `${result.score * 3.6}deg`);
    $('score-ring').style.setProperty('--score-color', info.color);
    $('assessment-card').style.borderColor = result.score >= 55 ? '#f0d8d3' : result.score >= 25 ? '#f2e5cc' : '#e4eae4';
    const list = $('findings-list');list.replaceChildren();
    if (!result.findings.length) list.append(el('p','finding-empty','No common scam indicators matched these rules. This does not confirm the message is legitimate.'));
    else result.findings.forEach(f => list.append(findingCard(f)));
    $('finding-count').textContent = `${result.findings.length} ${result.findings.length === 1 ? 'indicator' : 'indicators'}`;
    const extracted = $('extracted-list');extracted.replaceChildren();
    result.urls.forEach(url => extracted.append(el('div','extracted-url',url)));
    $('extracted-block').hidden = result.urls.length === 0;
    $('safe-next-text').textContent = result.next;
    $('message-results').hidden = false;
    $('message-results').scrollIntoView({behavior:'smooth',block:'nearest'});
  }

  function renderUrlResult(result) {
    const panel = $('url-results');panel.replaceChildren();panel.hidden = false;
    const info = scoreLabel(result.score);panel.dataset.risk = result.score >= 55 ? 'high' : result.score >= 25 ? 'medium' : 'low';
    panel.append(el('h3','url-result-title',info.heading),el('div','url-domain',result.url.hostname),el('p','', 'This is a local structure check only. The site was not visited and its reputation was not checked.'));
    if (!result.findings.length) panel.append(el('p','', 'No common structural warning signs matched. A normal-looking address can still lead to unsafe content.'));
    else {
      const list = document.createElement('ul');
      result.findings.forEach(f => list.append(el('li','',f.title)));
      panel.append(list);
    }
  }

  $('message-input').addEventListener('input', event => { $('char-count').textContent = `${event.target.value.length.toLocaleString()} / 10,000`; });
  $('message-form').addEventListener('submit', event => {
    event.preventDefault();
    const text = $('message-input').value.trim();
    if (!text) { $('message-input').focus(); $('message-input').setCustomValidity('Paste a message to check.'); $('message-input').reportValidity(); $('message-input').setCustomValidity(''); return; }
    renderMessage(text);
  });
  $('sample-button').addEventListener('click', () => { $('message-input').value = SAMPLE; $('char-count').textContent = `${SAMPLE.length} / 10,000`; $('message-input').focus(); });
  $('clear-button').addEventListener('click', () => { $('message-input').value = ''; $('char-count').textContent = '0 / 10,000'; $('message-results').hidden = true; $('url-input').value = ''; $('url-results').hidden = true; $('message-input').focus(); });
  $('dismiss-results').addEventListener('click', () => { $('message-results').hidden = true; });
  $('url-form').addEventListener('submit', event => {
    event.preventDefault();
    try { renderUrlResult(analyzeUrl($('url-input').value)); }
    catch (error) { const panel=$('url-results');panel.replaceChildren(el('h3','url-result-title','Could not check this address'),el('p','',error.message));panel.dataset.risk='medium';panel.hidden=false; }
  });

  // Small, reusable test surface for browser console/manual QA; no test code runs on page load.
  window.ScamShield = Object.freeze({analyzeMessage, analyzeUrl, extractUrls});
})();