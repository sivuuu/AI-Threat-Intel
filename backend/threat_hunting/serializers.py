from rest_framework import serializers
from threat_hunting.models import SecurityLog, Watchlist, DetectionRule, Alert, Incident, AnalystActionAudit


class SecurityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityLog
        fields = '__all__'


class WatchlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Watchlist
        fields = '__all__'


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    rule_name = serializers.ReadOnlyField(source='rule.name')
    rule_type = serializers.ReadOnlyField(source='rule.rule_type')

    class Meta:
        model = Alert
        fields = '__all__'


class AnalystActionAuditSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalystActionAudit
        fields = '__all__'


class IncidentSerializer(serializers.ModelSerializer):
    audit_logs = AnalystActionAuditSerializer(many=True, read_only=True)
    alerts = AlertSerializer(many=True, read_only=True)

    class Meta:
        model = Incident
        fields = '__all__'


class LogIngestionSerializer(serializers.Serializer):
    raw_content = serializers.CharField(required=False, allow_blank=True)
    file_format = serializers.ChoiceField(choices=['json', 'csv', 'syslog'], default='json')
    source_name = serializers.CharField(required=False, default='manual_upload')
