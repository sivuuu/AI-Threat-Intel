import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, Sparkles, AlertTriangle, 
  CheckCircle2, XCircle, Clock, User, Server, Globe, 
  FileText, Download, Check, RefreshCw, Send, Lock, 
  ChevronRight, ArrowLeft, AlertOctagon, HelpCircle, Eye
} from 'lucide-react';
import { 
  fetchIncidentDetail, fetchIncidentTimeline, 
  runAiInvestigation, performTriageAction, fetchIncidentReport 
} from '../services/api';

const LANGGRAPH_STAGES = [
  { id: 'input_validation', label: '1. Input Validation & Quarantining' },
  { id: 'deterministic_detection', label: '2. Deterministic Rule Matching' },
  { id: 'event_correlation', label: '3. Entity & Time Window Correlation' },
  { id: 'hypothesis_generation', label: '4. Bounded Hypothesis (Local Qwen)' },
  { id: 'evidence_verification', label: '5. Deterministic Evidence Verification' },
  { id: 'report_generation', label: '6. Report Synthesis' },
];

export default function IncidentView({ incidentId, onBack, onStatusUpdated }) {
  const [incident, setIncident] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [activeStageIndex, setActiveStageIndex] = useState(0);

  // Triage state
  const [triageAction, setTriageAction] = useState('CONFIRM_FINDING');
  const [analystNotes, setAnalystNotes] = useState('');
  const [triageSubmitting, setTriageSubmitting] = useState(false);
  const [triageSuccess, setTriageSuccess] = useState('');

  // Timeline filters
  const [timelineFilter, setTimelineFilter] = useState('ALL'); // ALL, LOG, ALERT
  const [highlightedEventId, setHighlightedEventId] = useState(null);

  // Export report modal
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [copiedReport, setCopiedReport] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [incData, tlData] = await Promise.all([
        fetchIncidentDetail(incidentId),
        fetchIncidentTimeline(incidentId),
      ]);
      setIncident(incData);
      setTimeline(tlData.timeline || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [incidentId]);

  const handleRunInvestigation = async () => {
    setInvestigating(true);
    setActiveStageIndex(0);

    // Animate stage progress for feedback
    const interval = setInterval(() => {
      setActiveStageIndex(prev => (prev < 4 ? prev + 1 : prev));
    }, 1200);

    try {
      const resp = await runAiInvestigation(incidentId);
      clearInterval(interval);
      setActiveStageIndex(5);
      setIncident(resp.incident);
      loadData();
      if (onStatusUpdated) onStatusUpdated();
    } catch (err) {
      clearInterval(interval);
      alert('AI investigation failed: ' + err.message);
    } finally {
      setTimeout(() => setInvestigating(false), 800);
    }
  };

  const handleTriageSubmit = async () => {
    if (!analystNotes.trim()) {
      alert('Please provide analyst notes explaining the rationale for this triage decision.');
      return;
    }
    setTriageSubmitting(true);
    setTriageSuccess('');

    try {
      const resp = await performTriageAction(incidentId, triageAction, analystNotes);
      setIncident(resp.incident);
      setTriageSuccess(`Action '${triageAction}' applied and recorded in immutable audit log.`);
      setAnalystNotes('');
      loadData();
      if (onStatusUpdated) onStatusUpdated();
      setTimeout(() => setTriageSuccess(''), 3000);
    } catch (err) {
      alert('Triage action failed: ' + err.message);
    } finally {
      setTriageSubmitting(false);
    }
  };

  const handleOpenReport = async () => {
    try {
      const rep = await fetchIncidentReport(incidentId);
      setReportData(rep);
      setIsReportModalOpen(true);
    } catch (err) {
      alert('Failed to generate report: ' + err.message);
    }
  };

  const handleCopyReportMarkdown = () => {
    if (!reportData) return;
    const md = `
# INCIDENT INVESTIGATION REPORT: ${reportData.incident_summary?.incident_id}
**Classification:** ${reportData.report_metadata?.classification}
**Generated At:** ${reportData.report_metadata?.generated_at}
**Lead Analyst:** ${reportData.report_metadata?.analyst}

---

## 1. Executive Summary
${reportData.investigation_findings?.ai_executive_summary}

**Evidence Grounding Score:** ${reportData.investigation_findings?.grounding_verification?.grounding_score ?? 100}%
**Evidence Sufficient:** ${reportData.investigation_findings?.is_evidence_sufficient ? 'YES' : 'NO - INSUFFICIENT EVIDENCE'}

---

## 2. 4-Tier Evidence & Threat Taxonomy

### [EVIDENCE] Confirmed Evidence
${(reportData.taxonomy_classification?.confirmed_evidence || []).map(e => `- [${e.supporting_event_ids?.join(', ')}] ${e.claim}`).join('\n')}

### [ALERT] Rule-Based Detection Alerts
${(reportData.taxonomy_classification?.rule_based_alerts || []).map(a => `- **${a.title}** (${a.severity}): ${a.description} [${a.event_ids?.join(', ')}]`).join('\n')}

### [HYPOTHESIS] Bounded AI Hypotheses
${(reportData.taxonomy_classification?.ai_hypotheses || []).map(h => `- **Confidence: ${h.confidence}**: ${h.hypothesis}\n  *Rationale:* ${h.rationale}`).join('\n')}

### [UNKNOWN] Unknowns & Blind Spots
${(reportData.taxonomy_classification?.unknowns_and_blind_spots || []).map(u => `- ${u}`).join('\n')}

---

## 3. Recommended Defensive Checks
${(reportData.actionable_guidance?.defensive_hardening_checks || []).map(d => `- ${d}`).join('\n')}

---

## 4. Analyst Audit Trail
${(reportData.analyst_audit_trail || []).map(a => `- [${a.timestamp}] **${a.analyst_name}** performed *${a.action_type}*: ${a.notes}`).join('\n')}
`;
    navigator.clipboard.writeText(md);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem', color: '#94a3b8' }}>
        <RefreshCw size={28} className="spin" style={{ marginBottom: '1rem' }} />
        <p>Loading incident telemetry & correlation state...</p>
      </div>
    );
  }

  if (!incident) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center' }}>
        <p>Incident not found.</p>
        <button className="btn btn-secondary" onClick={onBack} style={{ marginTop: '1rem' }}>
          Back to Incidents
        </button>
      </div>
    );
  }

  const verification = incident.verification_report || {};
  const groundingScore = verification.grounding_score ?? 100;
  const verifiedCitations = verification.verified_citations || [];
  const invalidCitations = verification.hallucinated_citations || [];

  const filteredTimeline = timeline.filter(item => {
    if (timelineFilter === 'LOG') return item.type === 'LOG_EVENT';
    if (timelineFilter === 'ALERT') return item.type === 'DETERMINISTIC_ALERT';
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      
      {/* Navigation & Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={onBack} style={{ padding: '0.4rem 0.75rem' }}>
            <ArrowLeft size={16} /> Back
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span className="mono" style={{ fontSize: '0.95rem', color: '#38bdf8', fontWeight: '700' }}>
                {incident.incident_id}
              </span>
              <span className={`badge badge-${incident.severity.toLowerCase()}`}>
                {incident.severity}
              </span>
              <span className="badge badge-purple">
                {incident.status}
              </span>
            </div>
            <h1 style={{ fontSize: '1.35rem', fontWeight: '800', color: '#f8fafc', marginTop: '0.2rem' }}>
              {incident.title}
            </h1>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button 
            className="btn btn-secondary"
            onClick={handleOpenReport}
          >
            <FileText size={15} /> Export Report
          </button>
          <button 
            className="btn btn-ai"
            onClick={handleRunInvestigation}
            disabled={investigating}
          >
            <Sparkles size={16} />
            {investigating ? 'Running LangGraph Bounded Workflow...' : 'Run Bounded AI Investigation'}
          </button>
        </div>
      </div>

      {/* Incident Entity Bar */}
      <div className="card" style={{ padding: '1rem 1.5rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', fontSize: '0.825rem' }}>
        <div>
          <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <User size={14} /> Primary Target User
          </span>
          <div style={{ fontWeight: '700', color: '#f1f5f9', marginTop: '0.2rem' }}>
            {incident.primary_user || 'Unknown'}
          </div>
        </div>

        <div>
          <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Server size={14} /> Primary Host
          </span>
          <div style={{ fontWeight: '700', color: '#f1f5f9', marginTop: '0.2rem' }}>
            {incident.primary_host || 'Unknown'}
          </div>
        </div>

        <div>
          <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Globe size={14} /> Source IP Address
          </span>
          <div className="mono" style={{ fontWeight: '700', color: '#38bdf8', marginTop: '0.2rem' }}>
            {incident.primary_ip || 'Internal / Segmented'}
          </div>
        </div>

        <div>
          <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Clock size={14} /> Correlated Events
          </span>
          <div style={{ fontWeight: '700', color: '#f1f5f9', marginTop: '0.2rem' }}>
            {incident.event_count} events ({incident.alerts?.length || 0} alerts)
          </div>
        </div>
      </div>

      {/* LangGraph Bounded Workflow Stage Visualizer */}
      {(investigating || incident.ai_investigation_status === 'COMPLETED') && (
        <div className="card" style={{ padding: '1.25rem 1.5rem', background: 'rgba(15, 23, 42, 0.9)', borderColor: 'rgba(168, 85, 247, 0.3)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Sparkles size={16} color="#c084fc" />
              <strong style={{ fontSize: '0.9rem', color: '#f1f5f9' }}>
                LangGraph Bounded State Machine Workflow
              </strong>
            </div>
            <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              Model: <strong style={{ color: '#c084fc' }}>{incident.llm_model_used || 'Local Qwen'}</strong>
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.5rem' }}>
            {LANGGRAPH_STAGES.map((stg, idx) => {
              const isDone = incident.ai_investigation_status === 'COMPLETED' || idx < activeStageIndex;
              const isCurrent = investigating && idx === activeStageIndex;

              return (
                <div 
                  key={stg.id}
                  style={{
                    padding: '0.65rem 0.75rem',
                    borderRadius: '8px',
                    fontSize: '0.72rem',
                    fontWeight: '600',
                    border: '1px solid',
                    background: isCurrent 
                      ? 'rgba(168, 85, 247, 0.2)' 
                      : isDone ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.03)',
                    borderColor: isCurrent 
                      ? '#a855f7' 
                      : isDone ? '#10b981' : 'rgba(255,255,255,0.08)',
                    color: isCurrent 
                      ? '#f3e8ff' 
                      : isDone ? '#34d399' : '#64748b',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    transition: 'all 0.3s ease'
                  }}
                >
                  {isDone ? (
                    <CheckCircle2 size={13} color="#10b981" />
                  ) : isCurrent ? (
                    <RefreshCw size={13} className="spin" color="#a855f7" />
                  ) : (
                    <Clock size={13} color="#64748b" />
                  )}
                  {stg.label}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Main Investigation Split View: 4-Tier Taxonomy vs Timeline */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.45fr 1fr', gap: '1.5rem' }}>
        
        {/* Left Column: 4-Tier Findings & Evidence Verification */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

          {/* AI Executive Summary Card */}
          <div className="card" style={{ padding: '1.5rem', borderLeft: '4px solid #38bdf8' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FileText size={18} color="#38bdf8" /> AI-Assisted Incident Synthesis
              </h3>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {incident.is_evidence_sufficient ? (
                  <span className="badge badge-verified">Evidence Sufficient</span>
                ) : (
                  <span className="badge badge-critical">INSUFFICIENT EVIDENCE</span>
                )}
              </div>
            </div>

            <p style={{ fontSize: '0.875rem', color: '#e2e8f0', lineHeight: '1.6' }}>
              {incident.ai_summary || (
                <span style={{ color: '#94a3b8', fontStyle: 'italic' }}>
                  No AI investigation has been conducted for this incident yet. Click "Run Bounded AI Investigation" above.
                </span>
              )}
            </p>

            {/* Zero-Hallucination Evidence Verification Metrics */}
            {incident.ai_investigation_status === 'COMPLETED' && (
              <div style={{ 
                marginTop: '1.25rem', 
                padding: '0.85rem 1rem', 
                background: 'rgba(8, 12, 22, 0.7)', 
                borderRadius: '8px', 
                border: '1px solid var(--border-light)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '0.75rem',
                fontSize: '0.8rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <ShieldCheck size={18} color={groundingScore >= 90 ? "#10b981" : "#f59e0b"} />
                  <div>
                    <span style={{ color: '#94a3b8' }}>Evidence Grounding Score:</span>{' '}
                    <strong style={{ color: groundingScore >= 90 ? '#34d399' : '#fbbf24', fontSize: '0.95rem' }}>
                      {groundingScore}%
                    </strong>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem' }}>
                  <span style={{ color: '#94a3b8' }}>
                    Verified Citations: <strong style={{ color: '#38bdf8' }}>{verifiedCitations.length}</strong>
                  </span>
                  {invalidCitations.length > 0 ? (
                    <span style={{ color: '#f87171' }}>
                      Unverified / Hallucinated: <strong>{invalidCitations.length}</strong>
                    </span>
                  ) : (
                    <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <Check size={13} /> Zero Hallucinations
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* 4-TIER TAXONOMY DISPLAY */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            
            {/* TIER 1: Confirmed Evidence [EVIDENCE] */}
            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
                <span className="badge badge-verified" style={{ padding: '0.25rem 0.65rem' }}>
                  [EVIDENCE]
                </span>
                <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#f8fafc' }}>
                  Confirmed Evidence (Ground-Truth Logs)
                </h4>
              </div>

              {(!incident.confirmed_evidence || incident.confirmed_evidence.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No confirmed evidence items generated yet.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {incident.confirmed_evidence.map((ev, idx) => (
                    <div key={idx} style={{ 
                      padding: '0.75rem', 
                      background: 'rgba(16, 185, 129, 0.05)', 
                      border: '1px solid rgba(16, 185, 129, 0.2)', 
                      borderRadius: '8px',
                      fontSize: '0.825rem'
                    }}>
                      <div style={{ color: '#e2e8f0', marginBottom: '0.4rem' }}>
                        {ev.claim}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Supporting Logs:</span>
                        {(ev.supporting_event_ids || []).map(eid => (
                          <span 
                            key={eid} 
                            className="citation-chip"
                            onClick={() => setHighlightedEventId(eid)}
                            title="Click to locate on timeline"
                          >
                            [{eid}]
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* TIER 2: Rule-Based Alerts [ALERT] */}
            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
                <span className="badge badge-high" style={{ padding: '0.25rem 0.65rem' }}>
                  [ALERT]
                </span>
                <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#f8fafc' }}>
                  Rule-Based Alerts (Deterministic Triggers)
                </h4>
              </div>

              {(!incident.alerts || incident.alerts.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No deterministic rule alerts linked to this incident.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {incident.alerts.map((al, idx) => (
                    <div key={idx} style={{ 
                      padding: '0.75rem', 
                      background: 'rgba(249, 115, 22, 0.05)', 
                      border: '1px solid rgba(249, 115, 22, 0.2)', 
                      borderRadius: '8px',
                      fontSize: '0.825rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                        <strong style={{ color: '#fdba74' }}>{al.title}</strong>
                        <span className={`badge badge-${al.severity.toLowerCase()}`} style={{ fontSize: '0.68rem' }}>
                          {al.severity}
                        </span>
                      </div>
                      <p style={{ color: '#cbd5e1', marginBottom: '0.4rem' }}>{al.description}</p>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Trigger Logs:</span>
                        {(al.event_ids || []).map(eid => (
                          <span 
                            key={eid} 
                            className="citation-chip"
                            onClick={() => setHighlightedEventId(eid)}
                          >
                            [{eid}]
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* TIER 3: AI Hypotheses [HYPOTHESIS] */}
            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
                <span className="badge badge-purple" style={{ padding: '0.25rem 0.65rem' }}>
                  [HYPOTHESIS]
                </span>
                <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#f8fafc' }}>
                  AI-Assisted Hypotheses (Bounded Reasoning)
                </h4>
              </div>

              {(!incident.ai_hypotheses || incident.ai_hypotheses.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No AI hypotheses formulated yet.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {incident.ai_hypotheses.map((hyp, idx) => (
                    <div key={idx} style={{ 
                      padding: '0.75rem', 
                      background: 'rgba(168, 85, 247, 0.05)', 
                      border: '1px solid rgba(168, 85, 247, 0.25)', 
                      borderRadius: '8px',
                      fontSize: '0.825rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                        <strong style={{ color: '#d8b4fe' }}>Attack Scenario Hypothesis #{idx+1}</strong>
                        <span className="badge badge-purple" style={{ fontSize: '0.68rem' }}>
                          Confidence: {hyp.confidence}
                        </span>
                      </div>
                      <p style={{ color: '#f1f5f9', fontWeight: '600', marginBottom: '0.35rem' }}>
                        {hyp.hypothesis}
                      </p>
                      {hyp.rationale && (
                        <p style={{ fontSize: '0.78rem', color: '#94a3b8', marginBottom: '0.4rem', fontStyle: 'italic' }}>
                          Rationale: {hyp.rationale}
                        </p>
                      )}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Correlated Citations:</span>
                        {(hyp.supporting_event_ids || []).map(eid => (
                          <span 
                            key={eid} 
                            className="citation-chip"
                            onClick={() => setHighlightedEventId(eid)}
                          >
                            [{eid}]
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* TIER 4: Unknowns & Blind Spots [UNKNOWN] */}
            <div className="card" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.85rem' }}>
                <span className="badge" style={{ background: 'rgba(100, 116, 139, 0.2)', color: '#94a3b8', border: '1px solid #64748b' }}>
                  [UNKNOWN]
                </span>
                <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#f8fafc' }}>
                  Unknowns & Telemetry Blind Spots
                </h4>
              </div>

              {(!incident.unknowns_and_gaps || incident.unknowns_and_gaps.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: '#64748b' }}>No telemetry gaps identified.</p>
              ) : (
                <ul style={{ paddingLeft: '1.25rem', fontSize: '0.825rem', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {incident.unknowns_and_gaps.map((unk, idx) => (
                    <li key={idx}>{unk}</li>
                  ))}
                </ul>
              )}
            </div>

            {/* Recommended Defensive Checks */}
            {incident.defensive_checks && incident.defensive_checks.length > 0 && (
              <div className="card" style={{ padding: '1.25rem' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#f8fafc', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <ShieldCheck size={16} color="#34d399" /> Recommended Defensive Checks & Hardening
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.825rem' }}>
                  {incident.defensive_checks.map((check, idx) => (
                    <div key={idx} style={{ padding: '0.6rem 0.8rem', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', borderLeft: '3px solid #10b981' }}>
                      {check}
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>

          {/* Human-in-the-Loop Analyst Triage Action Bar */}
          <div className="card" style={{ padding: '1.5rem', background: 'rgba(14, 23, 42, 0.95)', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: '#f8fafc', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Lock size={16} color="#38bdf8" /> Human-in-the-Loop Triage Decision
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '1.25rem' }}>
              AI serves strictly as an advisor. Analysts must review evidence and record formal decisions.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: '600', color: '#94a3b8', display: 'block', marginBottom: '0.4rem' }}>
                  Select Action:
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.6rem' }}>
                  <button 
                    type="button"
                    className={`btn ${triageAction === 'CONFIRM_FINDING' ? 'btn-success' : 'btn-secondary'}`}
                    onClick={() => setTriageAction('CONFIRM_FINDING')}
                    style={{ fontSize: '0.78rem' }}
                  >
                    Confirm Finding
                  </button>
                  <button 
                    type="button"
                    className={`btn ${triageAction === 'REJECT_FINDING' ? 'btn-danger' : 'btn-secondary'}`}
                    onClick={() => setTriageAction('REJECT_FINDING')}
                    style={{ fontSize: '0.78rem' }}
                  >
                    Reject / False Pos
                  </button>
                  <button 
                    type="button"
                    className={`btn ${triageAction === 'ESCALATE' ? 'btn-danger' : 'btn-secondary'}`}
                    onClick={() => setTriageAction('ESCALATE')}
                    style={{ fontSize: '0.78rem' }}
                  >
                    Escalate to CSIRT
                  </button>
                  <button 
                    type="button"
                    className={`btn ${triageAction === 'RESOLVE' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setTriageAction('RESOLVE')}
                    style={{ fontSize: '0.78rem' }}
                  >
                    Resolve Incident
                  </button>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: '600', color: '#94a3b8', display: 'block', marginBottom: '0.4rem' }}>
                  Analyst Rationale & Notes (Required for Audit Trail):
                </label>
                <textarea 
                  className="textarea"
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  placeholder="Document your evidence verification rationale, containment steps taken, or false positive reason..."
                  style={{ height: '80px', fontSize: '0.825rem' }}
                />
              </div>

              {triageSuccess && (
                <div style={{ padding: '0.6rem 0.8rem', background: 'rgba(16, 185, 129, 0.1)', color: '#34d399', borderRadius: '6px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Check size={14} /> {triageSuccess}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button 
                  className="btn btn-primary"
                  onClick={handleTriageSubmit}
                  disabled={triageSubmitting}
                >
                  <Send size={14} />
                  {triageSubmitting ? 'Recording Audit...' : 'Submit Triage Decision'}
                </button>
              </div>
            </div>

            {/* Audit Trail List */}
            {incident.audit_logs && incident.audit_logs.length > 0 && (
              <div style={{ marginTop: '1.5rem', borderTop: '1px solid var(--border-light)', paddingTop: '1rem' }}>
                <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: '700', textTransform: 'uppercase' }}>
                  Immutable Audit History ({incident.audit_logs.length})
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
                  {incident.audit_logs.map((audit) => (
                    <div key={audit.id} style={{ fontSize: '0.75rem', background: 'rgba(0,0,0,0.3)', padding: '0.5rem 0.75rem', borderRadius: '6px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8' }}>
                        <span><strong>{audit.analyst_name}</strong> • {audit.action_type}</span>
                        <span className="mono">{new Date(audit.timestamp).toLocaleTimeString()}</span>
                      </div>
                      {audit.notes && (
                        <div style={{ color: '#e2e8f0', marginTop: '0.2rem' }}>
                          "{audit.notes}"
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

        </div>

        {/* Right Column: Unified Chronological Timeline */}
        <div className="card" style={{ padding: '1.25rem', height: 'fit-content' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: '#f8fafc' }}>
              Correlated Event Timeline
            </h3>
            <div style={{ display: 'flex', gap: '0.35rem' }}>
              <button 
                className={`btn ${timelineFilter === 'ALL' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
                onClick={() => setTimelineFilter('ALL')}
              >
                All
              </button>
              <button 
                className={`btn ${timelineFilter === 'ALERT' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
                onClick={() => setTimelineFilter('ALERT')}
              >
                Alerts
              </button>
              <button 
                className={`btn ${timelineFilter === 'LOG' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
                onClick={() => setTimelineFilter('LOG')}
              >
                Logs
              </button>
            </div>
          </div>

          <p style={{ fontSize: '0.78rem', color: '#94a3b8', marginBottom: '1rem' }}>
            Clicking any event citation pill in the investigation workbench highlights that exact timestamp here.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '800px', overflowY: 'auto' }}>
            {filteredTimeline.map((item, idx) => {
              const isHighlighted = highlightedEventId === item.id;
              const isAlert = item.type === 'DETERMINISTIC_ALERT';

              return (
                <div 
                  key={idx}
                  id={`timeline-event-${item.id}`}
                  style={{
                    padding: '0.85rem',
                    borderRadius: '8px',
                    border: '1px solid',
                    background: isHighlighted 
                      ? 'rgba(56, 189, 248, 0.15)' 
                      : isAlert ? 'rgba(249, 115, 22, 0.06)' : 'rgba(15, 23, 42, 0.6)',
                    borderColor: isHighlighted 
                      ? '#38bdf8' 
                      : isAlert ? 'rgba(249, 115, 22, 0.3)' : 'var(--border-light)',
                    boxShadow: isHighlighted ? '0 0 15px rgba(56, 189, 248, 0.3)' : 'none',
                    transition: 'all 0.2s ease',
                    fontSize: '0.8rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                    <span className="mono" style={{ color: '#38bdf8', fontWeight: '700', fontSize: '0.75rem' }}>
                      {item.id}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
                    <span className={`badge badge-${item.severity.toLowerCase()}`} style={{ fontSize: '0.65rem' }}>
                      {item.severity}
                    </span>
                    <span className="badge badge-purple" style={{ fontSize: '0.65rem' }}>
                      {item.event_type}
                    </span>
                  </div>

                  <div style={{ color: '#e2e8f0', fontWeight: '500', marginBottom: '0.35rem' }}>
                    {item.summary || item.title}
                  </div>

                  {item.command_line && (
                    <div className="code-box" style={{ fontSize: '0.7rem', maxHeight: '60px' }}>
                      {item.command_line}
                    </div>
                  )}

                  {item.has_prompt_injection && (
                    <div style={{ marginTop: '0.35rem' }}>
                      <span className="badge badge-injection" style={{ fontSize: '0.65rem' }}>
                        <AlertOctagon size={10} /> Quarantined Hostile Injection
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

      </div>

      {/* Export Report Modal */}
      {isReportModalOpen && reportData && (
        <div className="modal-overlay" onClick={() => setIsReportModalOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '850px' }}>
            <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-light)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: '700', color: '#f8fafc' }}>
                  Incident Investigation Report
                </h3>
                <span className="mono" style={{ fontSize: '0.75rem', color: '#38bdf8' }}>
                  {reportData.incident_summary?.incident_id} • Strictly Confidential
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn btn-secondary" onClick={handleCopyReportMarkdown}>
                  {copiedReport ? <Check size={14} color="#34d399" /> : <FileText size={14} />}
                  {copiedReport ? 'Copied Markdown!' : 'Copy Markdown'}
                </button>
                <button 
                  onClick={() => setIsReportModalOpen(false)}
                  style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
                >
                  <XCircle size={20} />
                </button>
              </div>
            </div>

            <div style={{ padding: '1.5rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1.25rem', fontSize: '0.85rem' }}>
              <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px' }}>
                <h4 style={{ fontWeight: '700', color: '#f8fafc', marginBottom: '0.4rem' }}>Executive Summary</h4>
                <p style={{ color: '#cbd5e1', lineHeight: '1.6' }}>
                  {reportData.investigation_findings?.ai_executive_summary}
                </p>
              </div>

              <div>
                <h4 style={{ fontWeight: '700', color: '#f8fafc', marginBottom: '0.5rem' }}>
                  Confirmed Evidence [EVIDENCE]
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {(reportData.taxonomy_classification?.confirmed_evidence || []).map((e, i) => (
                    <div key={i} style={{ padding: '0.5rem 0.75rem', background: 'rgba(16, 185, 129, 0.05)', borderRadius: '6px' }}>
                      <span className="mono" style={{ color: '#38bdf8', marginRight: '0.5rem' }}>
                        [{e.supporting_event_ids?.join(', ')}]
                      </span>
                      {e.claim}
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h4 style={{ fontWeight: '700', color: '#f8fafc', marginBottom: '0.5rem' }}>
                  AI Hypotheses [HYPOTHESIS]
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {(reportData.taxonomy_classification?.ai_hypotheses || []).map((h, i) => (
                    <div key={i} style={{ padding: '0.5rem 0.75rem', background: 'rgba(168, 85, 247, 0.05)', borderRadius: '6px' }}>
                      <strong>Confidence {h.confidence}:</strong> {h.hypothesis}
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ padding: '0.75rem', background: 'rgba(244, 63, 94, 0.08)', borderRadius: '8px', borderLeft: '3px solid #f43f5e' }}>
                <strong style={{ color: '#fb7185' }}>Policy Constraint Notice:</strong>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                  {reportData.actionable_guidance?.human_authorization_notice}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
