# SYSX end-to-end harness

Drives SYSX's own web interface (through Flask's test client, with the real scheduler and scanners) against a lab
application: register target → add credentials → scan → check findings against a profile → scan again → open every page.
The harness exits 0 only if every *must* finding appears, no scan fails, the pages all load, and the safety audit passes.

**Use it only against applications you run yourself.** Never point it at anything you do not own.

## Profiles (`e2e/profiles/*.json`)

| Profile | Target | Notes |
|---|---|---|
| `sysx-lab` | SYSX's own lab app (`tests/lab_phase4.py`) | Run automatically by `tests/test_e2e_harness.py`; no setup |
| `dvwa` | DVWA at security level *low* | Needs a logged-in session cookie (below) |
| `juice-shop` | OWASP Juice Shop | Optional bearer token; only a small *must* list |

A profile lists `must` findings (the run fails without them) and `may` findings (reported, never failing).
`stable: true` additionally requires the second scan to produce the same findings.

## DVWA

```bash
docker compose -f e2e/docker-compose.yml up -d dvwa db
```

1. Open http://127.0.0.1:4280/setup.php and click *Create / Reset Database*; log in as `admin` / `password`.
2. In *DVWA Security* set the level to **Low**.
3. Copy your session cookie from your browser's developer tools and run:

```bash
python -m e2e dvwa http://127.0.0.1:4280 --secret dvwa-session='PHPSESSID=<value>; security=low'
```

SYSX never logs in through a form, which is why the cookie is supplied. The profile excludes `/logout.php`, `/setup.php`
and `/security.php`.

## Juice Shop

```bash
docker compose -f e2e/docker-compose.yml up -d juice-shop
python -m e2e juice-shop http://127.0.0.1:3000
# optional authenticated run: --secret juice-token=<JWT from your own login>
```

Juice Shop renders mostly in JavaScript, which the crawler does not execute, so expect few findings.

## Options

`--callback-url URL` (SSRF checks, thorough intensity), `--no-rescan`, `--timeout SECONDS`, `--json`, and a path to your own
JSON profile instead of a profile name.

## Caveat

The DVWA and Juice Shop profiles were written from those applications' documented behaviour and have **not** been run
(the development environment had no Docker or network). Adjust their `must` lists after your first run.
