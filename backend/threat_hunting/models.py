import uuid
from django.db import models
from django.utils import timezone


class SecurityLog(models.Model):
    """
    Normalized security event record ingested from untrusted raw log sources.
    Sanitized, secret-redacted, and indexed.
    """
    SEVERITY_CHOICES = [
        ('INFO', 'Info'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    log_id = models.CharField(max_length=64, unique=True, db_index=True)
    timestamp = models.DateTimeField(db_index=True)
    source = models.CharField(max_length=64, db_index=True)  # e.g., auth, sysmon, web, firewall
    event_type = models.CharField(max_length=64, db_index=True)  # auth_failure, process_created, etc.
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='INFO', db_index=True)

    # Normalized Entity Fields
    source_ip = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    destination_ip = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    username = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    hostname = models.CharField(max_length=128, blank=True, null=True, db_index=True)
    process_name = models.CharField(max_length=256, blank=True, null=True)
    command_line = models.TextField(blank=True, null=True)

    # Security & Sanitization Metadata
    sanitized_payload = models.JSONField(default=dict)
    raw_data_preview = models.TextField(blank=True, null=True)
    has_prompt_injection = models.BooleanField(default=False)
    prompt_injection_details = models.JSONField(default=dict, blank=True)
    redacted_secrets_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'username']),
            models.Index(fields=['timestamp', 'source_ip']),
            models.Index(fields=['event_type', 'severity']),
        ]

    def __str__(self):
        return f"[{self.log_id}] {self.timestamp.isoformat()} {self.event_type} ({self.severity})"


class Watchlist(models.Model):
    """
    Configurable threat intelligence watchlist for IOC detection.
    """
    TYPE_CHOICES = [
        ('IP', 'IP Address'),
        ('DOMAIN', 'Domain'),
        ('HASH', 'File Hash'),
        ('USERNAME', 'Target Username'),
    ]
    SEVERITY_CHOICES = [
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    watch_type = models.CharField(max_length=16, choices=TYPE_CHOICES)
    value = models.CharField(max_length=256, db_index=True)
    threat_actor = models.CharField(max_length=128, blank=True, default='Unknown / Suspicious')
    category = models.CharField(max_length=128, blank=True, default='C2 / Known Malicious')
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='HIGH')
    confidence = models.IntegerField(default=90)
    notes = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.watch_type}:{self.value} ({self.threat_actor})"


class DetectionRule(models.Model):
    """
    Deterministic detection rule executed against normalized log streams.
    """
    RULE_TYPE_CHOICES = [
        ('REPEATED_AUTH_FAILURE', 'Repeated Authentication Failures'),
        ('UNUSUAL_LOGIN_SEQUENCE', 'Unusual Login Sequence'),
        ('SUSPICIOUS_PROCESS', 'Suspicious Process Execution'),
        ('WATCHLIST_MATCH', 'Threat Watchlist Match'),
    ]
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    rule_id = models.CharField(max_length=64, unique=True, db_index=True)
    name = models.CharField(max_length=256)
    description = models.TextField()
    rule_type = models.CharField(max_length=32, choices=RULE_TYPE_CHOICES)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='MEDIUM')
    time_window_minutes = models.IntegerField(default=15)
    threshold = models.IntegerField(default=5)
    parameters = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    mitre_attack_id = models.CharField(max_length=64, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.rule_id}] {self.name} ({self.severity})"


class Incident(models.Model):
    """
    Correlated security incident grouping related events and alerts.
    Contains bounded AI investigation output and audit history.
    """
    STATUS_CHOICES = [
        ('TRIAGE', 'Triage'),
        ('IN_PROGRESS', 'In Progress'),
        ('CONFIRMED', 'Confirmed Incident'),
        ('REJECTED', 'Rejected / False Positive'),
        ('ESCALATED', 'Escalated to Tier-3'),
        ('RESOLVED', 'Resolved'),
    ]
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    AI_STATUS_CHOICES = [
        ('NOT_STARTED', 'Not Started'),
        ('RUNNING', 'Running Investigation'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]

    incident_id = models.CharField(max_length=64, unique=True, db_index=True)
    title = models.CharField(max_length=256)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='MEDIUM')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default='TRIAGE')
    lead_analyst = models.CharField(max_length=128, default='SOC Analyst')

    correlation_key = models.CharField(max_length=256, blank=True, default='')
    time_range_start = models.DateTimeField(null=True, blank=True)
    time_range_end = models.DateTimeField(null=True, blank=True)
    event_count = models.IntegerField(default=0)

    # Core Correlated Entities
    primary_user = models.CharField(max_length=128, blank=True, default='')
    primary_host = models.CharField(max_length=128, blank=True, default='')
    primary_ip = models.CharField(max_length=64, blank=True, default='')
    associated_event_ids = models.JSONField(default=list)

    # AI-Assisted Bounded Investigation Artifacts
    ai_investigation_status = models.CharField(max_length=32, choices=AI_STATUS_CHOICES, default='NOT_STARTED')
    ai_summary = models.TextField(blank=True, default='')
    ai_hypotheses = models.JSONField(default=list)
    confirmed_evidence = models.JSONField(default=list)
    rule_based_alerts_summary = models.JSONField(default=list)
    unknowns_and_gaps = models.JSONField(default=list)
    recommended_steps = models.JSONField(default=list)
    defensive_checks = models.JSONField(default=list)
    verification_report = models.JSONField(default=dict)
    is_evidence_sufficient = models.BooleanField(default=True)
    llm_model_used = models.CharField(max_length=64, blank=True, default='')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"[{self.incident_id}] {self.title} - {self.status}"


class Alert(models.Model):
    """
    Deterministic rule-triggered alert linked to triggering logs.
    """
    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('INVESTIGATING', 'Investigating'),
        ('CONFIRMED', 'Confirmed'),
        ('DISMISSED', 'Dismissed'),
    ]
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    alert_id = models.CharField(max_length=64, unique=True, db_index=True)
    rule = models.ForeignKey(DetectionRule, on_delete=models.SET_NULL, null=True, related_name='alerts')
    title = models.CharField(max_length=256)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='MEDIUM')
    description = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    target_user = models.CharField(max_length=128, blank=True, null=True)
    source_ip = models.CharField(max_length=64, blank=True, null=True)
    target_host = models.CharField(max_length=128, blank=True, null=True)
    event_ids = models.JSONField(default=list)
    evidence_count = models.IntegerField(default=0)
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default='NEW')

    incident = models.ForeignKey(Incident, on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.alert_id}] {self.title} ({self.severity})"


class AnalystActionAudit(models.Model):
    """
    Immutable audit trail for all analyst triage decisions, annotations, and actions.
    """
    ACTION_CHOICES = [
        ('CONFIRM_FINDING', 'Confirm Finding'),
        ('REJECT_FINDING', 'Reject Finding'),
        ('ANNOTATE', 'Add Annotation / Note'),
        ('ESCALATE', 'Escalate Incident'),
        ('DISMISS_ALERT', 'Dismiss Alert'),
        ('RUN_AI_INVESTIGATION', 'Execute AI Investigation'),
        ('EXPORT_REPORT', 'Export Report'),
        ('ASSOCIATE_EVENT', 'Associate Event to Incident'),
    ]

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='audit_logs')
    analyst_name = models.CharField(max_length=128, default='SOC Analyst')
    action_type = models.CharField(max_length=32, choices=ACTION_CHOICES)
    previous_status = models.CharField(max_length=32, blank=True, default='')
    new_status = models.CharField(max_length=32, blank=True, default='')
    notes = models.TextField(blank=True, default='')
    meta_data = models.JSONField(default=dict)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp.isoformat()} - {self.analyst_name}: {self.action_type}"
