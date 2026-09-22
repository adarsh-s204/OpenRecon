# OpenRecon

OpenRecon is a lawful OSINT prototype for understanding public digital exposure from user-provided emails, usernames, and domains.

## Features

- Dark cybersecurity dashboard built with HTML, CSS, JavaScript, and Bootstrap.
- Target input for email address, username, or domain name.
- Recon progress indicator and result summary cards.
- Public DNS collector for domain records.
- Public GitHub collector for usernames through the GitHub public API.
- Social profile candidate checks for Instagram, Facebook, and LinkedIn public URLs.
- Email normalization, public reference links, and domain-derived DNS checks.
- Rule-based finding normalization, correlation, and exposure score calculation.
- Findings table, custom canvas charts, SVG relationship graph, evidence links, and PDF report generation.

## Lawful Use Boundaries

OpenRecon does not bypass login, access private profiles, crack or test passwords, exploit websites, circumvent CAPTCHAs, access private records, or use illegal leaked databases. Review evidence links manually and keep collection limited to lawful public sources.

## Run

```bash
npm start
```

Then open:

```text
http://localhost:3000
```

