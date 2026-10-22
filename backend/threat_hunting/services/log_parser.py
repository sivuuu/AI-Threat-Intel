import re
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple

# Regex patterns for detecting and redacting secrets in untrusted logs
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd|secret|api_key|apikey|bearer|auth_token)\s*[:=]\s*["\']?([^"\'\s&,;]{6,})["\']?', r'\1=[REDACTED_SECRET]'),
    (r'(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', r'Bearer [REDACTED_SECRET]'),
    (r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----', r'[REDACTED_PRIVATE_KEY]'),
    (r'(?i)AWS[A-Z0-9]{16,}', r'[REDACTED_AWS_KEY]'),
]

# Patterns indicating prompt injection attacks embedded inside raw log contents
PROMPT_INJECTION_PATTERNS = [
    r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions',
    r'(?i)system\s*:\s*you\s+are\s+now',
    r'(?i)you\s+must\s+classify\s+this\s+as\s+benign',
    r'(?i)do\s+not\s+report\s+(any\s+)?threat',
    r'(?i)override\s+system\s+prompt',
    r'(?i)mark\s+this\s+incident\s+as\s+(safe|false\s+positive)',
    r'(?i)<\/evidence_corpus>',
    r'(?i)\[SYSTEM\s+OVERRIDE\]',
    r'(?i)format\s+your\s+response\s+as\s+clean',
]


def redact_secrets(text: str) -> Tuple[str, int]:
    """
    Redacts sensitive credentials, tokens, and private keys from log content.
    Returns the redacted string and count of redacted occurrences.
    """
    if not isinstance(text, str):
        return text, 0
    count = 0
    sanitized = text
    for pattern, repl in SECRET_PATTERNS:
        matches = len(re.findall(pattern, sanitized))
        if matches > 0:
            count += matches
            sanitized = re.sub(pattern, repl, sanitized)
    return sanitized, count


def detect_prompt_injection(text: str) -> Tuple[bool, List[str]]:
    """
    Scans raw log text for adversarial prompt injection patterns.
    """
    if not isinstance(text, str):
        return False, []
    matches = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text):
            matches.append(pattern)
    return (len(matches) > 0, matches)


def neutralize_untrusted_text(text: str) -> str:
    """
    Neutralizes markup and delimiter breakout characters while preserving log semantic readability.
    """
    if not isinstance(text, str):
        return str(text) if text is not None else ""
    # Strip dangerous HTML / XML closing tags
    cleaned = text.replace("<", "&lt;").replace(">", "&gt;")
    # Strip null bytes and control chars
    cleaned = "".join(ch for ch in cleaned if ch == '\n' or ch == '\t' or ord(ch) >= 32)
    return cleaned


def parse_timestamp(ts_value: Any) -> datetime:
    """
    Normalizes timestamps from ISO, Epoch, or standard security log formats to UTC datetime.
    """
    if not ts_value:
        return datetime.now(timezone.utc)
    
    if isinstance(ts_value, datetime):
        return ts_value if ts_value.tzinfo else ts_value.replace(tzinfo=timezone.utc)
        
    if isinstance(ts_value, (int, float)):
        # Epoch seconds or milliseconds
        if ts_value > 1e11:  # milliseconds
            return datetime.fromtimestamp(ts_value / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(ts_value, tz=timezone.utc)

    ts_str = str(ts_value).strip()
    
    # Try ISO-8601
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue

    # Fallback to current UTC time if unparseable
    return datetime.now(timezone.utc)


def sanitize_dict_or_list(obj: Any) -> Tuple[Any, int]:
    """
    Recursively redacts secrets from dictionary or list while preserving valid JSON structures.
    """
    secret_count = 0
    if isinstance(obj, dict):
        new_d = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ['password', 'passwd', 'secret', 'token', 'apikey', 'api_key', 'auth_token', 'bearer']):
                new_d[k] = "[REDACTED_SECRET]"
                secret_count += 1
            else:
                sub_v, sub_c = sanitize_dict_or_list(v)
                new_d[k] = sub_v
                secret_count += sub_c
        return new_d, secret_count
    elif isinstance(obj, list):
        new_l = []
        for item in obj:
            sub_i, sub_c = sanitize_dict_or_list(item)
            new_l.append(sub_i)
            secret_count += sub_c
        return new_l, secret_count
    elif isinstance(obj, str):
        redacted_str, c = redact_secrets(obj)
        return redacted_str, c
    else:
        return obj, 0


def normalize_log_record(raw: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    """
    Normalizes a single log record into standard schema:
    log_id, timestamp, source, event_type, severity, source_ip, destination_ip,
    username, hostname, process_name, command_line, sanitized_payload.
    """
    # 1. Determine or generate unique log_id
    log_id = str(raw.get('log_id') or raw.get('id') or raw.get('event_id') or f"LOG-{datetime.now().strftime('%Y%m%d%H%M')}-{index+1:04d}")

    # 2. Extract and normalize timestamp
    raw_ts = raw.get('timestamp') or raw.get('@timestamp') or raw.get('time') or raw.get('date') or raw.get('event_time')
    timestamp = parse_timestamp(raw_ts)

    # 3. Source & Event Type
    source = str(raw.get('source') or raw.get('log_source') or raw.get('sensor') or 'security_log').lower()
    raw_event_type = str(raw.get('event_type') or raw.get('action') or raw.get('event') or raw.get('message_type') or 'unknown').lower()

    # Map aliases to standard event_types
    event_type = 'unknown'
    if any(k in raw_event_type for k in ['fail', 'invalid', 'denied', 'bad_password', 'unauthorized', 'auth_failed']):
        event_type = 'authentication_failure'
    elif any(k in raw_event_type for k in ['success', 'logon', 'accepted', 'auth_success']):
        event_type = 'authentication_success'
    elif any(k in raw_event_type for k in ['process', 'exec', 'command', 'spawn', 'cmd']):
        event_type = 'process_creation'
    elif any(k in raw_event_type for k in ['network', 'connect', 'conn', 'traffic', 'flow']):
        event_type = 'network_connection'
    elif any(k in raw_event_type for k in ['dns', 'query', 'resolve']):
        event_type = 'dns_query'
    elif any(k in raw_event_type for k in ['privilege', 'escalat', 'sudo', 'runas']):
        event_type = 'privilege_escalation'
    else:
        event_type = raw_event_type[:64]

    # 4. Severity normalization
    raw_sev = str(raw.get('severity') or raw.get('level') or raw.get('priority') or 'INFO').upper()
    severity = 'INFO'
    if raw_sev in ['CRITICAL', 'CRIT', 'FATAL', 'EMERGENCY']:
        severity = 'CRITICAL'
    elif raw_sev in ['HIGH', 'ERR', 'ERROR']:
        severity = 'HIGH'
    elif raw_sev in ['MEDIUM', 'MED', 'WARN', 'WARNING']:
        severity = 'MEDIUM'
    elif raw_sev in ['LOW', 'NOTICE']:
        severity = 'LOW'

    # 5. Entity fields
    source_ip = raw.get('source_ip') or raw.get('src_ip') or raw.get('client_ip') or raw.get('src')
    destination_ip = raw.get('destination_ip') or raw.get('dest_ip') or raw.get('dst_ip') or raw.get('dst')
    username = raw.get('username') or raw.get('user') or raw.get('account') or raw.get('user_name') or raw.get('subject_user')
    hostname = raw.get('hostname') or raw.get('host') or raw.get('computer_name') or raw.get('endpoint')
    process_name = raw.get('process_name') or raw.get('process') or raw.get('image') or raw.get('app')
    command_line = raw.get('command_line') or raw.get('cmd') or raw.get('command') or raw.get('args') or raw.get('message')

    # Convert to clean strings
    source_ip = str(source_ip).strip() if source_ip else None
    destination_ip = str(destination_ip).strip() if destination_ip else None
    username = str(username).strip() if username else None
    hostname = str(hostname).strip() if hostname else None
    process_name = str(process_name).strip() if process_name else None
    command_line = str(command_line).strip() if command_line else None

    # 6. Prompt injection & secret redaction scanning across raw payload
    raw_json_str = json.dumps(raw, default=str)
    has_injection, injection_patterns = detect_prompt_injection(raw_json_str)
    sanitized_payload, secret_count = sanitize_dict_or_list(raw)

    # Clean command_line and process_name for safe handling
    if command_line:
        command_line, cmd_secrets = redact_secrets(command_line)
        secret_count += cmd_secrets
        command_line = neutralize_untrusted_text(command_line)

    if process_name:
        process_name = neutralize_untrusted_text(process_name)

    return {
        'log_id': log_id,
        'timestamp': timestamp,
        'source': source,
        'event_type': event_type,
        'severity': severity,
        'source_ip': source_ip,
        'destination_ip': destination_ip,
        'username': username,
        'hostname': hostname,
        'process_name': process_name,
        'command_line': command_line,
        'sanitized_payload': sanitized_payload,
        'raw_data_preview': str(raw)[:250],
        'has_prompt_injection': has_injection,
        'prompt_injection_details': {'matched_patterns': injection_patterns} if has_injection else {},
        'redacted_secrets_count': secret_count,
    }


def parse_security_logs(content_str: str, file_format: str = 'json') -> List[Dict[str, Any]]:
    """
    Parses untrusted log strings in JSON, JSON-lines, or CSV format into normalized record dictionaries.
    """
    records = []
    content_str = content_str.strip()

    if file_format == 'json' or content_str.startswith('[') or content_str.startswith('{'):
        try:
            # Try parsing as JSON array
            if content_str.startswith('['):
                parsed = json.loads(content_str)
                if isinstance(parsed, list):
                    for idx, item in enumerate(parsed):
                        if isinstance(item, dict):
                            records.append(normalize_log_record(item, idx))
                    return records
            # Try single JSON object
            elif content_str.startswith('{'):
                try:
                    parsed = json.loads(content_str)
                    records.append(normalize_log_record(parsed, 0))
                    return records
                except json.JSONDecodeError:
                    # Might be JSON Lines (NDJSON)
                    pass
        except Exception:
            pass

        # Try parsing as JSON Lines (one JSON per line)
        lines = content_str.splitlines()
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(normalize_log_record(item, idx))
            except Exception:
                # If not valid JSON, treat as Syslog line
                records.append(parse_syslog_line(line, idx))
        return records

    elif file_format == 'csv':
        try:
            f = io.StringIO(content_str)
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                records.append(normalize_log_record(dict(row), idx))
        except Exception as e:
            raise ValueError(f"Failed to parse CSV log format: {str(e)}")
        return records

    else:
        # Fallback line-by-line syslog parser
        lines = content_str.splitlines()
        for idx, line in enumerate(lines):
            line = line.strip()
            if line:
                records.append(parse_syslog_line(line, idx))
        return records


def parse_syslog_line(line: str, index: int) -> Dict[str, Any]:
    """
    Parses unstructured or syslog-style lines into standard normalized dictionary.
    """
    # Look for common IP patterns
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, line)
    source_ip = ips[0] if len(ips) > 0 else None
    dest_ip = ips[1] if len(ips) > 1 else None

    # Detect user
    user_match = re.search(r'(?:user|account|for)\s+([a-zA-Z0-9_\-\.]+)', line, re.IGNORECASE)
    username = user_match.group(1) if user_match else None

    # Detect event type
    line_lower = line.lower()
    event_type = 'security_event'
    severity = 'INFO'

    if 'failed' in line_lower or 'failure' in line_lower or 'invalid' in line_lower:
        event_type = 'authentication_failure'
        severity = 'MEDIUM'
    elif 'accepted' in line_lower or 'success' in line_lower:
        event_type = 'authentication_success'
        severity = 'INFO'
    elif 'powershell' in line_lower or 'bash' in line_lower or 'cmd.exe' in line_lower or 'sudo' in line_lower:
        event_type = 'process_creation'
        severity = 'HIGH' if ('-enc' in line_lower or 'curl' in line_lower or 'sh' in line_lower) else 'LOW'

    raw_dict = {
        'log_id': f"LOG-SYSLOG-{datetime.now().strftime('%Y%m%d%H%M')}-{index+1:04d}",
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'source': 'syslog',
        'event_type': event_type,
        'severity': severity,
        'source_ip': source_ip,
        'destination_ip': dest_ip,
        'username': username,
        'command_line': line,
        'raw_message': line,
    }
    return normalize_log_record(raw_dict, index)
