const API_BASE = 'http://localhost:8088/api';

export async function fetchDashboardStats() {
  const res = await fetch(`${API_BASE}/dashboard/stats/`);
  if (!res.ok) throw new Error('Failed to fetch dashboard stats');
  return res.json();
}

export async function fetchSecurityLogs(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${API_BASE}/logs/?${query}`);
  if (!res.ok) throw new Error('Failed to fetch security logs');
  return res.json();
}

export async function ingestLogs(data) {
  const isFormData = data instanceof FormData;
  const res = await fetch(`${API_BASE}/ingest/`, {
    method: 'POST',
    headers: isFormData ? {} : { 'Content-Type': 'application/json' },
    body: isFormData ? data : JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Upload failed' }));
    throw new Error(err.error || 'Log ingestion failed');
  }
  return res.json();
}

export async function fetchIncidents() {
  const res = await fetch(`${API_BASE}/incidents/`);
  if (!res.ok) throw new Error('Failed to fetch incidents');
  return res.json();
}

export async function fetchIncidentDetail(incidentId) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/`);
  if (!res.ok) throw new Error('Failed to fetch incident details');
  return res.json();
}

export async function fetchIncidentTimeline(incidentId) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/timeline/`);
  if (!res.ok) throw new Error('Failed to fetch incident timeline');
  return res.json();
}

export async function runAiInvestigation(incidentId, analystName = 'SOC Analyst') {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/investigate/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_name: analystName }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'AI investigation failed' }));
    throw new Error(err.error || 'AI investigation failed');
  }
  return res.json();
}

export async function performTriageAction(incidentId, actionType, notes, analystName = 'SOC Lead') {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/triage/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_type: actionType, notes, analyst_name: analystName }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Triage failed' }));
    throw new Error(err.error || 'Triage failed');
  }
  return res.json();
}

export async function fetchIncidentReport(incidentId) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/report/`);
  if (!res.ok) throw new Error('Failed to fetch report');
  return res.json();
}

export async function fetchDetectionRules() {
  const res = await fetch(`${API_BASE}/rules/`);
  if (!res.ok) throw new Error('Failed to fetch rules');
  return res.json();
}

export async function updateDetectionRule(ruleId, data) {
  const res = await fetch(`${API_BASE}/rules/${ruleId}/`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update rule');
  return res.json();
}

export async function fetchWatchlists() {
  const res = await fetch(`${API_BASE}/watchlists/`);
  if (!res.ok) throw new Error('Failed to fetch watchlists');
  return res.json();
}

export async function createWatchlist(data) {
  const res = await fetch(`${API_BASE}/watchlists/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to add watchlist item');
  return res.json();
}

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts/`);
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function fetchAuditLogs() {
  const res = await fetch(`${API_BASE}/audit/`);
  if (!res.ok) throw new Error('Failed to fetch audit logs');
  return res.json();
}

export async function seedSampleScenarios() {
  const res = await fetch(`${API_BASE}/seed-scenarios/`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to seed scenarios');
  return res.json();
}
