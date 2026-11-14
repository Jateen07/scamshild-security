# ScamShield

ScamShield is a static, browser-only message and URL checker. It uses transparent JavaScript rules to explain common scam indicators and practical next steps. It has no AI or threat-intelligence integration.

## Run it

Open `index.html` in a modern browser, or serve the folder with any static file server. No package install or build step is needed. The repository root contains the complete static website.

## Privacy and safety

- Message and URL analysis happens locally in the browser.
- The app does not save submitted content, send it to a server, or load submitted URLs.
- URL checks inspect the address string only; they do not check domain reputation or follow redirects.
- A score is a heuristic indicator score, not the probability that content is fraudulent. A low score is not proof of safety.

## What it checks

Message rules look for urgency, threats, prize claims, payment requests, requests for credentials or one-time codes, possible organization impersonation, shortened links, and remote-access requests. URLs are extracted and checked for IP addresses, embedded credentials or `@`, many subdomains, known shorteners, punycode, unusually long labels, redirect-style parameters, and plain HTTP.

Each matching indicator includes a plain-language explanation and a suggested action. Duplicate instances of the same rule contribute once to the message score. Different URL structures can each contribute once.

## Test cases

The following cases can be pasted into the app or evaluated with `ScamShield.analyzeMessage(...)` in the browser console:

1. Fake lottery: `Congratulations! You've won our lottery. Pay a processing fee to claim your prize.`
2. Bank suspension: `Your bank account will be suspended immediately. Verify your account today.`
3. OTP request: `Please reply with your OTP and password to confirm your identity.`
4. Payment request: `Send money now using gift cards to release your parcel.`
5. Shortened link: `Review this: https://bit.ly/account-review`
6. IP-based URL: `Sign in at http://192.0.2.10/login`
7. Ordinary conversation: `Are we still meeting for lunch at noon?`
8. Bank notification: `Your bank transfer of $24.00 was completed. If this wasn't you, call the number on your card.`
9. No URL: `The team meeting has moved to 3 pm.`
10. Empty input: Submit with the message field empty; the app requests text and keeps the page usable.

The project uses only HTML, CSS, and vanilla JavaScript. The app exposes `window.ScamShield` for manual checks and keeps the detection functions reusable.

## Deploy with GitHub Pages

1. Create a public repository and upload the files from this folder to the repository root.
2. Under **Settings → Pages**, select **Deploy from a branch**, choose the `main` branch and `/ (root)`, then save.
3. Open the GitHub Pages URL shown in the repository's Pages settings after deployment completes.

This is a static site and does not require backend hosting, API credentials, or build secrets.
