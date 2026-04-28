# BoostForge Digital Store

Arabic RTL Flask web app for SMM, games, accounts, apps, and gift cards.

## Stack
- Python 3.11 + Flask, SQLite (`database.db`)
- Jinja2 templates in `templates/`
- Static assets in `static/`
- Service catalogs in `data/` (JSON)
- RTL Arabic UI, Cairo font
- Theme inspired by ovoxz.com: dark navy + starry dotted background, right sidebar (login/register, theme toggle, social), red/gold hero banner, X-cut category cards
- CSS vars: `--bg:#070d1c`, `--panel:#0f1729`, `--panel-2:#111c33`, `--accent:#3b82f6`, `--accent-2:#00d4ff`, `--gold:#d4af37`
- Light theme toggle persisted via `localStorage('bf_theme')` and applied across all pages

## Workflow
- `Start application` → `python main.py` on port 5000 (webview)

## Routes
- `/` — home with category cubes
- `/games` — 5 popular games
- `/smm` — 1006 SMM services across 184 categories (collapsible + search). Source: pigolikes.com (+30% markup). Data: `data/smm_services.json`
- `/accounts`, `/accounts/netflix`, `/accounts/shahid` — account tiers (manual prices)
- `/apps` — 99 apps grid with search. Source: ovoxz.com (+10% markup). Data: `data/apps_services.json`. Icons in `static/apps/`
- `/apps/<id>` — order form with live price calculator (qty × markup_perc). Submit → WhatsApp deep link with order summary
- `/login`, `/register`, `/logout` — basic auth

## Apps data structure (`data/apps_services.json`)
Each item: `{id, name, perc, min_qty, max_qty, default_qty, starts_from_usd, instructions, image, local_image, markup_perc, markup_starts_from}`
- `perc` = original per-unit USD rate from ovoxz
- `markup_perc` = `perc × 1.1` (10% markup)
- `markup_starts_from` = `min_qty × markup_perc`
