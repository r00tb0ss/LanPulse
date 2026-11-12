# LanPulse roadmap

What is planned next, in the order it is likely to ship. Releases are small and built one at a time. Dates are not promised, and the order can change.

## 1. Hardening and release checks
- Tighter handling of backups: automatic pruning, one backup at a time, and a login required to create them.
- Verification of downloaded updates before they are installed.
- Clearer, friendlier errors when a backup cannot be restored.
- An automated browser check in CI that opens every tab and fails on any JavaScript error.

## 2. Release safety
- Fewer, larger releases, tried on a test instance first.
- One-click return to the previous version.
- Database upgrade checks and a start-up self-check that reports a broken setting plainly.
- Retention settings and a disk-space warning on the health board.

## 3. Better accuracy
- A "this finding is wrong" button on each device, so repeats stop and the rules improve.
- A known-good list for your own scanners, devices and address ranges.
- Alerts based on each device's normal traffic.
- The same confidence labels (confirmed, likely, weak) on every finding.

## 4. Alerts
- Quiet-hours schedules and routing by severity.
- A weekly summary next to the daily one.
- Block on UDM from honeypot sessions and map popups.
- Grouped alerts, a test button for every channel, and a small settings export and import file.

## 5. Everyday use
- A layout pass for phones and tablets on the busiest views.
- A first-run checklist driven by the health board.
- Search across devices, addresses, sessions and findings from one box.

## Later
User roles, an audit log, optional two-factor login, a combined incident view, API tokens, a metrics endpoint, several sites in one dashboard, Docker and Debian packages, a written threat model with a security policy, and an independent security test.

## Already shipped recently
Health board, quiet mode, verified backups with a restore tool, honeypot hash and SSH fingerprint intelligence, and honeypot attack filters with per-service host details. Password changes rotate the session signing secret; other existing sessions are invalidated while the changing browser receives a fresh session.
