import re
from datetime import timedelta
from typing import List, Dict, Any
from django.utils import timezone
from threat_hunting.models import SecurityLog, DetectionRule, Alert, Watchlist


# Default regexes for suspicious command-line execution and LOLBins
SUSPICIOUS_CLI_PATTERNS = [
    (r'(?i)powershell(\.exe)?\s+.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}', 'T1059.001', 'Encoded PowerShell execution detected'),
    (r'(?i)(curl|wget)\s+.*\|\s*(bash|sh|python)', 'T1059.004', 'Direct download-and-execute shell pipe detected'),
    (r'(?i)certutil(\.exe)?\s+.*-(urlcache|split|decode)', 'T1105', 'Ingress tool transfer using certutil LOLBin'),
    (r'(?i)vssadmin(\.exe)?\s+delete\s+shadows', 'T1490', 'Volume shadow copy deletion (Ransomware precursor)'),
    (r'(?i)whoami(\.exe)?\s+/priv', 'T1033', 'Security token / privilege enumeration via whoami /priv'),
    (r'(?i)(mimikatz|sekurlsa|lsadump|procdump.*lsass)', 'T1003.001', 'Credential dumping artifact or tool execution'),
    (r'(?i)rundll32(\.exe)?\s+.*(javascript|vbscript|dllregisterserver)', 'T1218.011', 'Suspicious proxy execution via rundll32'),
    (r'(?i)bash\s+-i\s+>&?\s+/dev/tcp/', 'T1059.004', 'Interactive bash reverse TCP shell command'),
    (r'(?i)net(\.exe)?\s+(user|localgroup\s+administrators)\s+.*\/add', 'T1136.001', 'Local account creation or administrator privilege escalation'),
    (r'(?i)reg(\.exe)?\s+save\s+hklm\\(sam|system|security)', 'T1003.002', 'Registry SAM hive extraction for offline credential cracking'),
]


def run_deterministic_detections(logs: List[SecurityLog]) -> List[Alert]:
    """
    Evaluates active deterministic detection rules against the provided list of normalized logs.
    Generates Alert records linked directly to the evidence event IDs.
    """
    if not logs:
        return []

    alerts_created = []

    # Sort logs chronologically
    sorted_logs = sorted(logs, key=lambda x: x.timestamp)
    all_active_rules = {r.rule_type: r for r in DetectionRule.objects.filter(is_active=True)}
    active_watchlists = list(Watchlist.objects.filter(is_active=True))

    # 1. EVALUATE: Repeated Authentication Failures
    rule_auth = all_active_rules.get('REPEATED_AUTH_FAILURE')
    if rule_auth:
        window_minutes = rule_auth.time_window_minutes or 15
        threshold = rule_auth.threshold or 5
        
        # Group failed attempts by IP and User
        ip_failures: Dict[str, List[SecurityLog]] = {}
        user_failures: Dict[str, List[SecurityLog]] = {}

        for log in sorted_logs:
            if log.event_type == 'authentication_failure':
                if log.source_ip:
                    ip_failures.setdefault(log.source_ip, []).append(log)
                if log.username:
                    user_failures.setdefault(log.username, []).append(log)

        # Check IP threshold
        for src_ip, fail_logs in ip_failures.items():
            if len(fail_logs) >= threshold:
                # Sliding window check
                for i in range(len(fail_logs) - threshold + 1):
                    window_logs = fail_logs[i:i + threshold]
                    time_diff = (window_logs[-1].timestamp - window_logs[0].timestamp).total_seconds() / 60.0
                    if time_diff <= window_minutes:
                        ev_ids = [l.log_id for l in window_logs]
                        alert_id = f"ALT-AUTH-IP-{src_ip.replace('.', '_')}-{window_logs[0].timestamp.strftime('%H%M%S')}"
                        alert, created = Alert.objects.get_or_create(
                            alert_id=alert_id,
                            defaults={
                                'rule': rule_auth,
                                'title': f"Repeated Auth Failures from IP: {src_ip} ({len(ev_ids)} attempts)",
                                'severity': rule_auth.severity,
                                'description': f"Detected {len(ev_ids)} consecutive authentication failures from source IP {src_ip} within {time_diff:.1f} minutes.",
                                'timestamp': window_logs[-1].timestamp,
                                'source_ip': src_ip,
                                'target_user': window_logs[0].username,
                                'target_host': window_logs[0].hostname,
                                'event_ids': ev_ids,
                                'evidence_count': len(ev_ids),
                            }
                        )
                        if created:
                            alerts_created.append(alert)
                        break

    # 2. EVALUATE: Unusual Login Sequence (Brute-force followed by Success or Priv-Esc)
    rule_seq = all_active_rules.get('UNUSUAL_LOGIN_SEQUENCE')
    if rule_seq:
        window_mins = rule_seq.time_window_minutes or 15
        # Search for pattern: >= 2 auth failures followed by auth success for the same user/ip
        user_timeline: Dict[str, List[SecurityLog]] = {}
        for log in sorted_logs:
            key = log.username or log.source_ip
            if key:
                user_timeline.setdefault(key, []).append(log)

        for key, events in user_timeline.items():
            failed_buffer = []
            for ev in events:
                if ev.event_type == 'authentication_failure':
                    failed_buffer.append(ev)
                elif ev.event_type == 'authentication_success':
                    # Check if there were failed logins right before this
                    if len(failed_buffer) >= 2:
                        earliest = failed_buffer[0].timestamp
                        if (ev.timestamp - earliest).total_seconds() / 60.0 <= window_mins:
                            ev_ids = [l.log_id for l in failed_buffer] + [ev.log_id]
                            alert_id = f"ALT-SEQ-COMPROMISE-{key.replace('.', '_')}-{ev.timestamp.strftime('%H%M%S')}"
                            alert, created = Alert.objects.get_or_create(
                                alert_id=alert_id,
                                defaults={
                                    'rule': rule_seq,
                                    'title': f"Unusual Login Sequence: Credential Guessing Succeeded for {key}",
                                    'severity': 'HIGH',
                                    'description': f"Target {key} experienced {len(failed_buffer)} failed login attempts followed by a successful authentication within {window_mins} minutes.",
                                    'timestamp': ev.timestamp,
                                    'target_user': ev.username,
                                    'source_ip': ev.source_ip,
                                    'target_host': ev.hostname,
                                    'event_ids': ev_ids,
                                    'evidence_count': len(ev_ids),
                                }
                            )
                            if created:
                                alerts_created.append(alert)
                    failed_buffer = []

    # 3. EVALUATE: Suspicious Process Events (CLI, LOLBins, Shells)
    rule_proc = all_active_rules.get('SUSPICIOUS_PROCESS')
    if rule_proc:
        for log in sorted_logs:
            cmd = log.command_line or ""
            proc = log.process_name or ""
            text_to_scan = f"{proc} {cmd}".strip()
            if not text_to_scan:
                continue

            for pattern, mitre_id, rationale in SUSPICIOUS_CLI_PATTERNS:
                if re.search(pattern, text_to_scan):
                    alert_id = f"ALT-PROC-{log.log_id}"
                    alert, created = Alert.objects.get_or_create(
                        alert_id=alert_id,
                        defaults={
                            'rule': rule_proc,
                            'title': f"Suspicious Process Execution: {rationale}",
                            'severity': 'HIGH',
                            'description': f"Command execution matched high-risk signature ({mitre_id}): '{cmd[:150]}'. Target Host: {log.hostname or 'Unknown'}, User: {log.username or 'Unknown'}.",
                            'timestamp': log.timestamp,
                            'target_user': log.username,
                            'source_ip': log.source_ip,
                            'target_host': log.hostname,
                            'event_ids': [log.log_id],
                            'evidence_count': 1,
                        }
                    )
                    if created:
                        alerts_created.append(alert)
                    break

    # 4. EVALUATE: Threat Watchlist Matching
    rule_wl = all_active_rules.get('WATCHLIST_MATCH')
    if rule_wl and active_watchlists:
        wl_ips = {w.value.strip().lower(): w for w in active_watchlists if w.watch_type == 'IP'}
        wl_users = {w.value.strip().lower(): w for w in active_watchlists if w.watch_type == 'USERNAME'}
        wl_domains = {w.value.strip().lower(): w for w in active_watchlists if w.watch_type == 'DOMAIN'}

        for log in sorted_logs:
            matched_entry = None
            matched_field = ""
            matched_val = ""

            if log.source_ip and log.source_ip.lower() in wl_ips:
                matched_entry = wl_ips[log.source_ip.lower()]
                matched_field = "Source IP"
                matched_val = log.source_ip
            elif log.destination_ip and log.destination_ip.lower() in wl_ips:
                matched_entry = wl_ips[log.destination_ip.lower()]
                matched_field = "Destination IP"
                matched_val = log.destination_ip
            elif log.username and log.username.lower() in wl_users:
                matched_entry = wl_users[log.username.lower()]
                matched_field = "Username"
                matched_val = log.username

            if matched_entry:
                alert_id = f"ALT-WATCHLIST-{log.log_id}"
                alert, created = Alert.objects.get_or_create(
                    alert_id=alert_id,
                    defaults={
                        'rule': rule_wl,
                        'title': f"Watchlist IOC Match: {matched_field} {matched_val}",
                        'severity': matched_entry.severity,
                        'description': f"Event matched threat watchlist entry '{matched_entry.value}' attributed to actor '{matched_entry.threat_actor}' ({matched_entry.category}). Confidence: {matched_entry.confidence}%.",
                        'timestamp': log.timestamp,
                        'target_user': log.username,
                        'source_ip': log.source_ip,
                        'target_host': log.hostname,
                        'event_ids': [log.log_id],
                        'evidence_count': 1,
                    }
                )
                if created:
                    alerts_created.append(alert)

    return alerts_created
