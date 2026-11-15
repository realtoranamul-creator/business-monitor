#!/usr/bin/env python3
"""
Cross-project infrastructure monitoring system.
Runs via GitHub Actions (independent of Vercel) every 10 minutes.
Checks website availability, Vercel deployments, API health, SSL certs.
Sends private email alerts to OWNER_PRIVATE_ALERT_EMAIL via Resend.
Never exposes the destination email in code, logs, or API responses.
"""
import json, os, sys, time, ssl, socket, hashlib, datetime, urllib.request, urllib.error, traceback
from pathlib import Path

# ─── Configuration ──────────────────────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent / "projects.json"
STATE_PATH = Path(os.environ.get("GITHUB_WORKSPACE", ".")) / "monitor-state.json"

# Secrets from GitHub Actions environment (never hardcoded)
VERCEL_TOKEN = os.environ.get("VERCEL_TOKEN", "")
VERCEL_TEAM_ID = os.environ.get("VERCEL_TEAM_ID", "team_Gtwjfz5HRs2VBPo6xJ7CP92u")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
OWNER_PRIVATE_ALERT_EMAIL = os.environ.get("OWNER_PRIVATE_ALERT_EMAIL", "")

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# ─── Utilities ──────────────────────────────────────────────────────────────
def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def now_epoch():
    return time.time()

def log(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")

def mask_email(email):
    """Mask email for safe display in logs/dashboards — never show full address."""
    if not email or "@" not in email:
        return "(not configured)"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"

# ─── State management (for dedup + recovery notifications) ──────────────────
def load_state():
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except:
            pass
    return {"incidents": {}, "last_run": None}

def save_state(state):
    state["last_run"] = now_iso()
    STATE_PATH.write_text(json.dumps(state, indent=2))

# ─── Alert dedup + suppression ──────────────────────────────────────────────
def should_alert(state, incident_key, severity, thresholds):
    """Determine if we should send an alert (dedup + recovery logic)."""
    incidents = state.get("incidents", {})
    existing = incidents.get(incident_key)
    now = now_epoch()

    if existing is None:
        # New incident — always alert
        return True, "new"

    last_alerted = existing.get("last_alerted", 0)
    last_severity = existing.get("severity", severity)
    status = existing.get("status", "open")

    if status == "resolved":
        # Previously resolved, now recurring — alert again
        return True, "recurring"

    # Incident is ongoing — check dedup window
    dedup_window = thresholds.get("dedup_window_minutes", 60) * 60
    if now - last_alerted < dedup_window:
        # Within dedup window — suppress unless severity escalated
        if severity_rank(severity) > severity_rank(last_severity):
            return True, "escalated"
        return False, "suppressed_dedup"

    # Past dedup window — send periodic reminder for ongoing incidents
    if severity in (SEVERITY_CRITICAL, SEVERITY_HIGH):
        return True, "reminder"
    return False, "suppressed_low"

def severity_rank(s):
    return {SEVERITY_LOW: 0, SEVERITY_MEDIUM: 1, SEVERITY_HIGH: 2, SEVERITY_CRITICAL: 3}.get(s, 0)

def update_state(state, incident_key, severity, status, details):
    """Update incident state after alerting."""
    incidents = state.setdefault("incidents", {})
    incidents[incident_key] = {
        "severity": severity,
        "status": status,
        "first_detected": incidents.get(incident_key, {}).get("first_detected", now_iso()),
        "last_detected": now_iso(),
        "last_alerted": now_epoch() if status != "resolved" else incidents.get(incident_key, {}).get("last_alerted", 0),
        "details": details,
    }

def check_recovery(state, incident_key, thresholds):
    """Check if a previously open incident has recovered."""
    incidents = state.get("incidents", {})
    existing = incidents.get(incident_key)
    if existing and existing.get("status") != "resolved":
        return True
    return False

# ─── Checks ─────────────────────────────────────────────────────────────────
def check_website(url, thresholds):
    """Check website availability + response time + SSL."""
    timeout = thresholds.get("website_timeout_seconds", 15)
    warn_ms = thresholds.get("response_time_warning_ms", 3000)
    crit_ms = thresholds.get("response_time_critical_ms", 10000)

    result = {"url": url, "status": "ok", "details": {}}

    try:
        start = time.time()
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "BusinessMonitor/1.0"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        elapsed_ms = int((time.time() - start) * 1000)
        result["details"]["http_status"] = resp.status
        result["details"]["response_time_ms"] = elapsed_ms

        if elapsed_ms > crit_ms:
            result["status"] = "critical"
            result["details"]["issue"] = f"Response time {elapsed_ms}ms exceeds {crit_ms}ms threshold"
        elif elapsed_ms > warn_ms:
            result["status"] = "warning"
            result["details"]["issue"] = f"Response time {elapsed_ms}ms exceeds {warn_ms}ms threshold"
    except urllib.error.HTTPError as e:
        result["status"] = "critical" if e.code >= 500 else "warning"
        result["details"]["issue"] = f"HTTP {e.code}"
    except urllib.error.URLError as e:
        result["status"] = "critical"
        result["details"]["issue"] = f"Connection failed: {str(e.reason)[:200]}"
    except socket.timeout:
        result["status"] = "critical"
        result["details"]["issue"] = f"Timeout after {timeout}s"
    except Exception as e:
        result["status"] = "critical"
        result["details"]["issue"] = f"Unexpected error: {str(e)[:200]}"

    return result

def check_ssl_cert(domain, thresholds):
    """Check SSL certificate expiration."""
    warn_days = thresholds.get("ssl_expiry_warning_days", 30)
    crit_days = thresholds.get("ssl_expiry_critical_days", 7)

    result = {"domain": domain, "status": "ok", "details": {}}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                    result["details"]["expiry_date"] = not_after
                    result["details"]["days_left"] = days_left
                    if days_left <= crit_days:
                        result["status"] = "critical"
                        result["details"]["issue"] = f"SSL expires in {days_left} days (critical: {crit_days}d)"
                    elif days_left <= warn_days:
                        result["status"] = "warning"
                        result["details"]["issue"] = f"SSL expires in {days_left} days (warning: {warn_days}d)"
    except Exception as e:
        result["status"] = "warning"
        result["details"]["issue"] = f"SSL check failed: {str(e)[:200]}"

    return result

def check_vercel_deployment(project_id, thresholds):
    """Check latest Vercel production deployment status."""
    result = {"project_id": project_id, "status": "ok", "details": {}}

    if not VERCEL_TOKEN:
        result["status"] = "unknown"
        result["details"]["issue"] = "VERCEL_TOKEN not configured"
        return result

    try:
        url = f"https://api.vercel.com/v6/deployments?projectId={project_id}&teamId={VERCEL_TEAM_ID}&limit=3&target=production"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {VERCEL_TOKEN}"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        deployments = data.get("deployments", [])

        if not deployments:
            result["status"] = "warning"
            result["details"]["issue"] = "No production deployments found"
            return result

        latest = deployments[0]
        state = latest.get("readyState", "?")
        created = latest.get("createdAt", 0)
        age_minutes = (now_epoch() - created / 1000) / 60 if created else 0

        result["details"]["latest_state"] = state
        result["details"]["latest_uid"] = latest.get("uid", "?")
        result["details"]["age_minutes"] = int(age_minutes)

        if state == "ERROR":
            result["status"] = "critical"
            result["details"]["issue"] = f"Latest production deployment FAILED (state={state})"
        elif state == "BUILDING" and age_minutes > 15:
            result["status"] = "warning"
            result["details"]["issue"] = f"Deployment building for {int(age_minutes)}min (stuck?)"
        elif state == "QUEUED" and age_minutes > 10:
            result["status"] = "warning"
            result["details"]["issue"] = f"Deployment queued for {int(age_minutes)}min"
        elif state == "READY":
            result["details"]["issue"] = None
        else:
            result["status"] = "warning"
            result["details"]["issue"] = f"Deployment state: {state}"

    except Exception as e:
        result["status"] = "warning"
        result["details"]["issue"] = f"Vercel API check failed: {str(e)[:200]}"

    return result

def check_gemini_health(thresholds):
    """Check Gemini API health + usage estimation."""
    result = {"service": "Google Gemini API", "status": "ok", "details": {}}

    if not GEMINI_API_KEY:
        result["status"] = "unknown"
        result["details"]["issue"] = "GEMINI_API_KEY not configured"
        return result

    try:
        # Simple models list call — validates API key + service availability
        url = "https://generativelanguage.googleapis.com/v1beta/models?key=" + GEMINI_API_KEY
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        models = data.get("models", [])
        result["details"]["models_available"] = len(models)
        result["details"]["api_responsive"] = True

    except urllib.error.HTTPError as e:
        if e.code == 429:
            result["status"] = "critical"
            result["details"]["issue"] = "Gemini API rate limited (429) — quota may be exhausted"
        elif e.code == 403:
            result["status"] = "critical"
            result["details"]["issue"] = "Gemini API key invalid/forbidden (403)"
        else:
            result["status"] = "warning"
            result["details"]["issue"] = f"Gemini API HTTP {e.code}"
    except Exception as e:
        result["status"] = "critical"
        result["details"]["issue"] = f"Gemini API unreachable: {str(e)[:200]}"

    return result

def check_resend_health():
    """Check Resend email service health."""
    result = {"service": "Resend Email", "status": "ok", "details": {}}

    if not RESEND_API_KEY:
        result["status"] = "unknown"
        result["details"]["issue"] = "RESEND_API_KEY not configured"
        return result

    try:
        url = "https://api.resend.com/domains"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {RESEND_API_KEY}"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        domains = data.get("data", [])
        result["details"]["domains_configured"] = len(domains)
        verified = [d for d in domains if d.get("status") == "verified"]
        result["details"]["domains_verified"] = len(verified)
        if not verified:
            result["status"] = "warning"
            result["details"]["issue"] = "No verified sending domains — alerts may fail to deliver"
    except Exception as e:
        result["status"] = "critical"
        result["details"]["issue"] = f"Resend API error: {str(e)[:200]}"

    return result

# ─── Email alerting ─────────────────────────────────────────────────────────
def send_alert_email(subject, body_html, severity):
    """Send alert email via Resend. Destination is OWNER_PRIVATE_ALERT_EMAIL secret."""
    if not RESEND_API_KEY:
        log("RESEND_API_KEY not set — cannot send email alert", "ERROR")
        return False, "no_api_key"

    if not OWNER_PRIVATE_ALERT_EMAIL:
        log("OWNER_PRIVATE_ALERT_EMAIL not set — cannot send alert", "ERROR")
        return False, "no_destination"

    config = json.loads(CONFIG_PATH.read_text())
    email_config = config.get("email", {})
    sender = email_config.get("sender", "alerts@hoquerealty.com")
    sender_name = email_config.get("sender_name", "Business Monitor")

    # Try primary sender; if domain not verified, Resend returns error
    # Fall back to onboarding@resend.dev (sends to Resend account owner email only)
    for from_addr in [sender, email_config.get("sender_fallback", "onboarding@resend.dev")]:
        payload = {
            "from": f"{sender_name} <{from_addr}>",
            "to": [OWNER_PRIVATE_ALERT_EMAIL],  # Private — never logged or exposed
            "subject": subject,
            "html": body_html,
        }

        try:
            req = urllib.request.Request(
                "https://api.resend.com/emails",
                data=json.dumps(payload).encode(),
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=15)
            data = json.loads(resp.read())
            email_id = data.get("id", "?")
            # Log WITHOUT the destination email address
            log(f"Alert email sent (id={email_id}, severity={severity}, from={from_addr}, to={mask_email(OWNER_PRIVATE_ALERT_EMAIL)})", "INFO")
            return True, email_id
        except urllib.error.HTTPError as e:
            error_body = e.read().decode()[:300]
            if e.code == 403 and "verify" in error_body.lower():
                # Domain not verified — try fallback sender
                log(f"Sender {from_addr} not verified, trying fallback...", "WARN")
                continue
            log(f"Resend API error {e.code}: {error_body}", "ERROR")
            return False, f"http_{e.code}"
        except Exception as e:
            log(f"Email send failed: {str(e)[:200]}", "ERROR")
            return False, str(e)[:100]

    return False, "all_senders_failed"

def build_alert_email(project_name, incident_key, severity, status, details, first_detected, last_detected):
    """Build professional HTML alert email. Never includes sensitive data."""
    severity_colors = {
        SEVERITY_CRITICAL: "#DC2626",
        SEVERITY_HIGH: "#EA580C",
        SEVERITY_MEDIUM: "#CA8A04",
        SEVERITY_LOW: "#2563EB",
    }
    color = severity_colors.get(severity, "#666")

    safe_details = json.dumps(details, indent=2) if details else "N/A"
    # Sanitize — never include passwords, keys, tokens
    sensitive_patterns = ["password", "apikey", "api_key", "token", "secret", "bearer", "authorization"]
    safe_details_lower = safe_details.lower()
    for pattern in sensitive_patterns:
        if pattern in safe_details_lower:
            safe_details = "(details redacted — may contain sensitive data)"

    status_text = "Ongoing" if status != "resolved" else "RESOLVED"
    recovery_note = """
    <tr><td colspan="2" style="padding:12px;background:#DCFCE7;border-radius:6px;color:#166534;">
    <strong>✓ RECOVERY:</strong> This issue has been resolved. No further action needed.
    </td></tr>""" if status == "resolved" else ""

    html = f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
<table style="width:100%;border-collapse:collapse;">
<tr><td colspan="2" style="background:{color};color:white;padding:16px;border-radius:6px 6px 0 0;">
<h2 style="margin:0;font-size:18px;">[{severity}] {project_name}</h2>
</td></tr>
<tr><td style="padding:8px 12px;border-bottom:1px solid #eee;font-weight:bold;width:140px;">Business:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{project_name}</td></tr>
<tr><td style="padding:8px 12px;border-bottom:1px solid #eee;font-weight:bold;">Affected service:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{incident_key}</td></tr>
<tr><td style="padding:8px 12px;border-bottom:1px solid #eee;font-weight:bold;">Severity:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;color:{color};font-weight:bold;">{severity}</td></tr>
<tr><td style="padding:8px 12px;border-bottom:1px solid #eee;font-weight:bold;">Status:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{status_text}</td></tr>
<tr><td style="padding:8px 12px;border-bottom:1px solid #eee;font-weight:bold;">First detected:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{first_detected}</td></tr>
<tr><td style="padding:8px 12px;border-bottom:1px solid #eee;font-weight:bold;">Last detected:</td><td style="padding:8px 12px;border-bottom:1px solid #eee;">{last_detected}</td></tr>
{recovery_note}
<tr><td colspan="2" style="padding:12px;background:#F9FAFB;border-radius:0 0 6px 6px;">
<p style="margin:0 0 8px;font-weight:bold;">Evidence (non-sensitive):</p>
<pre style="white-space:pre-wrap;font-size:12px;color:#374151;margin:0;">{safe_details}</pre>
</td></tr>
<tr><td colspan="2" style="padding:12px;font-size:11px;color:#6B7280;">
<p style="margin:0;">This is an automated alert from your Business Monitor system.</p>
<p style="margin:4px 0 0;">Reply-to: noreply (this mailbox is not monitored). Manage alerts in your GitHub repository settings.</p>
</td></tr>
</table>
</body></html>"""

    subject = f"[{severity}] {project_name} — {incident_key}"
    if status == "resolved":
        subject = f"[RESOLVED] {project_name} — {incident_key}"
    return subject, html

# ─── Main monitoring loop ───────────────────────────────────────────────────
def run_monitor():
    config = json.loads(CONFIG_PATH.read_text())
    thresholds = config.get("alert_thresholds", {})
    projects = config.get("projects", [])

    state = load_state()
    alerts_sent = 0
    recoveries_sent = 0
    issues_found = 0

    log(f"Monitoring {len(projects)} project(s) — destination: {mask_email(OWNER_PRIVATE_ALERT_EMAIL)}")

    for project in projects:
        pname = project.get("name", "?")
        domain = project.get("domain", "?")
        log(f"Checking {pname} ({domain})...")

        # 1. Website availability checks
        for route_url in project.get("critical_routes", []):
            result = check_website(route_url, thresholds)
            if result["status"] != "ok":
                issues_found += 1
                incident_key = f"Website: {route_url}"
                severity = SEVERITY_CRITICAL if result["status"] == "critical" else SEVERITY_MEDIUM

                should_send, reason = should_alert(state, incident_key, severity, thresholds)
                if should_send:
                    subject, html = build_alert_email(
                        pname, incident_key, severity, "open",
                        result["details"], now_iso(), now_iso()
                    )
                    sent, _ = send_alert_email(subject, html, severity)
                    if sent:
                        alerts_sent += 1
                        update_state(state, incident_key, severity, "open", result["details"])
            else:
                # Check recovery
                incident_key = f"Website: {route_url}"
                if check_recovery(state, incident_key, thresholds):
                    subject, html = build_alert_email(
                        pname, incident_key, SEVERITY_LOW, "resolved",
                        result["details"], state["incidents"][incident_key].get("first_detected", ""), now_iso()
                    )
                    sent, _ = send_alert_email(subject, html, "RESOLVED")
                    if sent:
                        recoveries_sent += 1
                    update_state(state, incident_key, SEVERITY_LOW, "resolved", result["details"])

        # 2. SSL certificate check
        ssl_result = check_ssl_cert(domain, thresholds)
        if ssl_result["status"] != "ok":
            issues_found += 1
            incident_key = f"SSL: {domain}"
            severity = SEVERITY_CRITICAL if ssl_result["status"] == "critical" else SEVERITY_MEDIUM
            should_send, reason = should_alert(state, incident_key, severity, thresholds)
            if should_send:
                subject, html = build_alert_email(pname, incident_key, severity, "open", ssl_result["details"], now_iso(), now_iso())
                sent, _ = send_alert_email(subject, html, severity)
                if sent:
                    alerts_sent += 1
                    update_state(state, incident_key, severity, "open", ssl_result["details"])

        # 3. Vercel deployment check
        vercel_pid = project.get("vercel_project_id")
        if vercel_pid:
            vresult = check_vercel_deployment(vercel_pid, thresholds)
            if vresult["status"] != "ok":
                issues_found += 1
                incident_key = f"Vercel deploy: {pname}"
                severity = SEVERITY_CRITICAL if vresult["status"] == "critical" else SEVERITY_HIGH
                should_send, reason = should_alert(state, incident_key, severity, thresholds)
                if should_send:
                    subject, html = build_alert_email(pname, incident_key, severity, "open", vresult["details"], now_iso(), now_iso())
                    sent, _ = send_alert_email(subject, html, severity)
                    if sent:
                        alerts_sent += 1
                        update_state(state, incident_key, severity, "open", vresult["details"])

        # 4. Gemini API health (if project uses Gemini)
        if project.get("uses_gemini"):
            gresult = check_gemini_health(thresholds)
            if gresult["status"] != "ok":
                issues_found += 1
                incident_key = f"Gemini API: {pname}"
                severity = SEVERITY_CRITICAL if gresult["status"] == "critical" else SEVERITY_MEDIUM
                should_send, reason = should_alert(state, incident_key, severity, thresholds)
                if should_send:
                    subject, html = build_alert_email(pname, incident_key, severity, "open", gresult["details"], now_iso(), now_iso())
                    sent, _ = send_alert_email(subject, html, severity)
                    if sent:
                        alerts_sent += 1
                        update_state(state, incident_key, severity, "open", gresult["details"])

    # 5. Global service checks (Resend)
    resend_result = check_resend_health()
    if resend_result["status"] == "critical":
        issues_found += 1
        incident_key = "Resend Email Service"
        should_send, reason = should_alert(state, incident_key, SEVERITY_CRITICAL, thresholds)
        if should_send:
            subject, html = build_alert_email("All Projects", incident_key, SEVERITY_CRITICAL, "open", resend_result["details"], now_iso(), now_iso())
            sent, _ = send_alert_email(subject, html, SEVERITY_CRITICAL)
            if sent:
                alerts_sent += 1
                update_state(state, incident_key, SEVERITY_CRITICAL, "open", resend_result["details"])

    save_state(state)
    log(f"Done. Issues: {issues_found}, Alerts sent: {alerts_sent}, Recoveries: {recoveries_sent}")
    return {"issues": issues_found, "alerts": alerts_sent, "recoveries": recoveries_sent}

if __name__ == "__main__":
    if not OWNER_PRIVATE_ALERT_EMAIL:
        log("OWNER_PRIVATE_ALERT_EMAIL is not set. Set it as a GitHub secret.", "ERROR")
        log(f"Destination (masked): {mask_email(OWNER_PRIVATE_ALERT_EMAIL)}")
        log("Monitoring will run but cannot send alerts until configured.", "WARN")
    try:
        result = run_monitor()
        sys.exit(0)
    except Exception as e:
        log(f"Monitor crashed: {e}", "ERROR")
        traceback.print_exc()
        sys.exit(1)
