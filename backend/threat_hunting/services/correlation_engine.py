from datetime import timedelta
from typing import List, Dict, Any, Optional
from django.utils import timezone
from threat_hunting.models import SecurityLog, Alert, Incident


def correlate_alerts_and_events(time_window_minutes: int = 60) -> List[Incident]:
    """
    Correlates active alerts and related security events into cohesive Incident clusters
    based on entity overlap (same user, source IP, or target host) within a sliding time window.
    """
    # Fetch all unassociated alerts or alerts marked NEW / INVESTIGATING
    unlinked_alerts = list(Alert.objects.filter(incident__isnull=True).order_by('timestamp'))
    if not unlinked_alerts:
        # Check existing incidents to update related log lists if needed
        return list(Incident.objects.all().order_by('-updated_at'))

    incidents_created = []

    # Cluster alerts by primary entity (user, source_ip, or target_host)
    clusters: Dict[str, List[Alert]] = {}
    for alert in unlinked_alerts:
        # Determine dominant correlation key
        entity_key = None
        if alert.target_user:
            entity_key = f"user:{alert.target_user.lower()}"
        elif alert.source_ip:
            entity_key = f"ip:{alert.source_ip}"
        elif alert.target_host:
            entity_key = f"host:{alert.target_host.lower()}"
        else:
            entity_key = f"general:{alert.timestamp.strftime('%Y%m%d%H')}"

        clusters.setdefault(entity_key, []).append(alert)

    for entity_key, alert_group in clusters.items():
        if not alert_group:
            continue

        # Sort group by timestamp
        alert_group.sort(key=lambda a: a.timestamp)
        first_alert = alert_group[0]
        last_alert = alert_group[-1]

        # Determine severity based on highest alert severity
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        max_sev_val = max(severity_order.get(a.severity, 1) for a in alert_group)
        highest_severity = {4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW'}.get(max_sev_val, 'MEDIUM')

        # Gather all event IDs across the alert group
        all_event_ids = set()
        for a in alert_group:
            all_event_ids.update(a.event_ids)

        # Pull any related logs matching the entity and time window (+/- 15 mins)
        time_min = first_alert.timestamp - timedelta(minutes=15)
        time_max = last_alert.timestamp + timedelta(minutes=15)

        prefix, val = entity_key.split(':', 1)
        related_log_qs = SecurityLog.objects.filter(timestamp__gte=time_min, timestamp__lte=time_max)
        if prefix == 'user':
            related_log_qs = related_log_qs.filter(username__iexact=val)
        elif prefix == 'ip':
            related_log_qs = related_log_qs.filter(source_ip=val)
        elif prefix == 'host':
            related_log_qs = related_log_qs.filter(hostname__iexact=val)

        for log in related_log_qs:
            all_event_ids.add(log.log_id)

        # Create or update incident
        incident_id = f"INC-{first_alert.timestamp.strftime('%Y%m%d')}-{entity_key.replace(':', '_').replace('.', '_')[:32]}"
        title = f"Correlated Activity: {alert_group[0].title.split(':')[0]} ({len(alert_group)} alerts)"
        if len(alert_group) > 1:
            title = f"Multi-Stage Suspicious Chain on {entity_key.upper()} ({len(alert_group)} correlated alerts)"

        incident, created = Incident.objects.get_or_create(
            incident_id=incident_id,
            defaults={
                'title': title,
                'severity': highest_severity,
                'status': 'TRIAGE',
                'correlation_key': entity_key,
                'time_range_start': time_min,
                'time_range_end': time_max,
                'event_count': len(all_event_ids),
                'primary_user': first_alert.target_user or '',
                'primary_host': first_alert.target_host or '',
                'primary_ip': first_alert.source_ip or '',
                'associated_event_ids': list(all_event_ids),
            }
        )

        if not created:
            # Update existing incident with new events and time range
            existing_ids = set(incident.associated_event_ids)
            existing_ids.update(all_event_ids)
            incident.associated_event_ids = list(existing_ids)
            incident.event_count = len(existing_ids)
            incident.time_range_end = max(incident.time_range_end or time_max, time_max)
            if severity_order.get(highest_severity, 1) > severity_order.get(incident.severity, 1):
                incident.severity = highest_severity
            incident.save()

        # Link alerts to this incident
        for a in alert_group:
            a.incident = incident
            a.save()

        incidents_created.append(incident)

    return incidents_created


def get_incident_timeline_data(incident: Incident) -> List[Dict[str, Any]]:
    """
    Returns ordered, enriched timeline events for an incident including both raw security logs
    and triggered deterministic alerts.
    """
    event_ids = incident.associated_event_ids or []
    logs = list(SecurityLog.objects.filter(log_id__in=event_ids).order_by('timestamp'))
    alerts = list(Alert.objects.filter(incident=incident).order_by('timestamp'))

    timeline = []

    # Add logs
    for log in logs:
        timeline.append({
            'type': 'LOG_EVENT',
            'id': log.log_id,
            'timestamp': log.timestamp.isoformat(),
            'event_type': log.event_type,
            'severity': log.severity,
            'source': log.source,
            'user': log.username,
            'source_ip': log.source_ip,
            'destination_ip': log.destination_ip,
            'hostname': log.hostname,
            'process_name': log.process_name,
            'command_line': log.command_line,
            'has_prompt_injection': log.has_prompt_injection,
            'redacted_secrets_count': log.redacted_secrets_count,
            'summary': f"{log.event_type} on {log.hostname or log.source_ip or 'endpoint'} ({log.username or 'unknown user'})",
        })

    # Add alerts
    for alert in alerts:
        timeline.append({
            'type': 'DETERMINISTIC_ALERT',
            'id': alert.alert_id,
            'timestamp': alert.timestamp.isoformat(),
            'event_type': 'ALERT_TRIGGERED',
            'severity': alert.severity,
            'source': 'detection_rule',
            'user': alert.target_user,
            'source_ip': alert.source_ip,
            'target_host': alert.target_host,
            'title': alert.title,
            'description': alert.description,
            'event_ids': alert.event_ids,
            'summary': alert.title,
        })

    # Sort unified timeline by timestamp
    timeline.sort(key=lambda x: x['timestamp'])
    return timeline
