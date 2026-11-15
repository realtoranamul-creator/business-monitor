# Business Monitor — Cross-Project Infrastructure Alerting

Automated monitoring system for all your business websites and applications.
Runs on **GitHub Actions** (independent of Vercel — alerts work even when your
hosting is down) and sends emergency alerts to your **private personal Gmail**.

## What It Monitors

| Check | Description | Alert Trigger |
|-------|-------------|---------------|
| Website availability | HTTP HEAD checks on critical routes | Timeout, 5xx, connection failure |
| SSL certificates | Certificate expiration | <30 days warning, <7 days critical |
| Vercel deployments | Latest production deploy status | ERROR, stuck BUILDING, QUEUED too long |
| Gemini API | Health + quota check | 429 (quota exhausted), 403 (key invalid), unreachable |
| Resend email | Sending domain status | No verified domains, API errors |

## Privacy Protection (Critical)

Your personal Gmail address is **never** stored in:
- Source code
- Configuration files (`projects.json`)
- Frontend JavaScript or HTML
- API responses
- Application logs (masked as `a***@gmail.com`)
- Monitoring dashboards

The destination email is stored **only** as an encrypted GitHub Actions secret
(`OWNER_PRIVATE_ALERT_EMAIL`), accessible only to the repo owner.

## Setup — One Required Action

### Set your private Gmail as a GitHub secret

1. Go to: **https://github.com/realtoranamul-creator/business-monitor/settings/secrets/actions**
2. Click **"New repository secret"**
3. **Name**: `OWNER_PRIVATE_ALERT_EMAIL`
4. **Value**: your personal Gmail address
5. Click **"Add secret"**

That's it. The monitoring system will start sending alerts to that address.
No one else can see this value — GitHub encrypts it.

### Already configured (automated)

These secrets were set during setup:
- `VERCEL_TOKEN` — for deployment monitoring
- `VERCEL_TEAM_ID` — your Vercel team
- `RESEND_API_KEY` — for sending alert emails
- `GEMINI_API_KEY` — for Gemini API health checks

## How Alerts Appear

**Subject**: `[CRITICAL] Hoque Realty — Website: https://hoquerealty.com`

**Body** includes:
- Business name
- Affected service
- Severity (CRITICAL / HIGH / MEDIUM / LOW)
- First + last detected timestamps
- Non-sensitive evidence (no passwords, tokens, or keys)
- Recovery notification when issue resolves

## Alert Severity + Dedup

| Severity | When emailed | Behavior |
|----------|-------------|----------|
| CRITICAL | Immediately | + reminders every 60 min if ongoing |
| HIGH | Immediately | + reminders every 60 min if ongoing |
| MEDIUM | Grouped/throttled | 60-min dedup window |
| LOW | Daily digest | Suppressed if duplicate |

Duplicate suppression prevents flooding your Gmail. You get:
1. Initial alert when issue detected
2. Escalation if severity increases
3. Periodic reminders for ongoing CRITICAL/HIGH
4. Recovery notification when issue resolves

## Adding New Projects

Edit `projects.json` to add a new business website:

```json
{
  "name": "IronBedTruck",
  "business": "IronBedTruck",
  "domain": "ironbedtruck.com",
  "url": "https://ironbedtruck.com",
  "vercel_project_id": "prj_xxx",
  "critical_routes": [
    "https://ironbedtruck.com",
    "https://ironbedtruck.com/api/health"
  ],
  "uses_supabase": true,
  "uses_gemini": false,
  "uses_resend": true,
  "uses_stripe": true,
  "gemini_budget_usd": 0,
  "notes": "Truck bed inventory + supplier feeds"
}
```

## Manual Trigger

To test the monitoring immediately:
1. Go to: **https://github.com/realtoranamul-creator/business-monitor/actions**
2. Select **"Infrastructure Monitor"** workflow
3. Click **"Run workflow"**

## Monitoring Schedule

- Runs **every 10 minutes** via GitHub Actions cron
- Independent of Vercel (runs on GitHub infrastructure)
- Free tier: 2000 min/month for private repos (each run uses ~1 min)

## Current Project Coverage

| Project | Domain | Status |
|---------|--------|--------|
| Hoque Realty | hoquerealty.com | **Monitored** |
| GigTry | gigtry.com | Not found on this Vercel/GitHub account |
| LeadHunting AI | leadhunting.app | Not found on this Vercel/GitHub account |
| IronBedTruck | ironbedtruck.com | Not found on this Vercel/GitHub account |

To add missing projects: deploy them to Vercel, then add their config to `projects.json`.

## Security Notes

- Alert emails never contain API keys, passwords, tokens, or customer data
- The `from` address is `alerts@hoquerealty.com` (requires Resend domain verification)
- If domain not verified, falls back to `onboarding@resend.dev` (sends to Resend account owner only)
- The `reply-to` is noreply (mailbox not monitored)
- State file (`monitor-state.json`) tracks incidents for dedup — contains no sensitive data
