import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Terminal, 
  Cpu, Lock, Activity, Play, Eye, FileText, CheckCircle2, 
  Sparkles, AlertOctagon, UserX, ArrowRight
} from 'lucide-react';

export default function Dashboard({ 
  stats, 
  incidents, 
  onSelectIncident, 
  onSeedScenarios, 
  loadingSeed,
  onNavigateTab 
}) {
  const llm = stats?.llm_status || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      
      {/* Top Banner: Local LLM & Safety Posture */}
      <div className="card" style={{ 
        padding: '1.25rem 1.75rem', 
        background: 'linear-gradient(135deg, rgba(14, 23, 42, 0.9) 0%, rgba(15, 23, 42, 0.7) 100%)',
        borderColor: 'rgba(56, 189, 248, 0.25)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ 
            width: '46px', 
            height: '46px', 
            borderRadius: '10px', 
            background: 'rgba(0, 242, 254, 0.1)', 
            border: '1px solid rgba(0, 242, 254, 0.3)',
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            color: '#38bdf8'
          }}>
            <Cpu size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <h2 style={{ fontSize: '1.15rem', fontWeight: '700', color: '#f8fafc' }}>
                Local AI Threat Hunting Engine Active
              </h2>
              <span className="badge badge-verified">
                <span className="status-dot active"></span> Local Ollama: {llm.configured_model || 'qwen3:8b'}
              </span>
            </div>
            <p style={{ fontSize: '0.825rem', color: '#94a3b8', marginTop: '0.2rem' }}>
              Bounded LangGraph State Machine • Zero-Hallucination Verification • Untrusted Log Sanitization
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ 
            padding: '0.4rem 0.85rem', 
            background: 'rgba(16, 185, 129, 0.08)', 
            borderRadius: '8px', 
            border: '1px solid rgba(16, 185, 129, 0.25)',
            fontSize: '0.8rem',
            color: '#34d399',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}>
            <Lock size={14} /> Response Action: Human Authorization Required
          </div>
          <button 
            className="btn btn-primary"
            onClick={onSeedScenarios}
            disabled={loadingSeed}
          >
            <Play size={15} />
            {loadingSeed ? 'Simulating...' : 'Simulate Attack Scenarios'}
          </button>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', 
        gap: '1.25rem' 
      }}>
        {/* Metric 1 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Active Incidents</span>
            <div style={{ color: '#f43f5e', background: 'rgba(244, 63, 94, 0.1)', padding: '6px', borderRadius: '8px' }}>
              <ShieldAlert size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: '800', color: '#f8fafc', marginTop: '0.5rem' }}>
            {stats?.active_incidents ?? 0}
          </div>
          <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.25rem' }}>
            Requiring analyst triage & investigation
          </div>
        </div>

        {/* Metric 2 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Rule-Based Alerts</span>
            <div style={{ color: '#f59e0b', background: 'rgba(245, 158, 11, 0.1)', padding: '6px', borderRadius: '8px' }}>
              <AlertTriangle size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: '800', color: '#f8fafc', marginTop: '0.5rem' }}>
            {stats?.total_alerts ?? 0}
          </div>
          <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.25rem' }}>
            Deterministic rule matches triggered
          </div>
        </div>

        {/* Metric 3 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Prompt Injections Blocked</span>
            <div style={{ color: '#ef4444', background: 'rgba(239, 68, 68, 0.1)', padding: '6px', borderRadius: '8px' }}>
              <AlertOctagon size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: '800', color: '#fca5a5', marginTop: '0.5rem' }}>
            {stats?.prompt_injections_blocked ?? 0}
          </div>
          <div style={{ fontSize: '0.78rem', color: '#f87171', marginTop: '0.25rem' }}>
            Adversarial log payloads neutralized
          </div>
        </div>

        {/* Metric 4 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Normalized Logs</span>
            <div style={{ color: '#38bdf8', background: 'rgba(56, 189, 248, 0.1)', padding: '6px', borderRadius: '8px' }}>
              <Terminal size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: '800', color: '#f8fafc', marginTop: '0.5rem' }}>
            {stats?.total_logs ?? 0}
          </div>
          <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.25rem' }}>
            Ingested across JSON, CSV & Syslog
          </div>
        </div>

        {/* Metric 5 */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>Secrets Redacted</span>
            <div style={{ color: '#10b981', background: 'rgba(16, 185, 129, 0.1)', padding: '6px', borderRadius: '8px' }}>
              <Lock size={18} />
            </div>
          </div>
          <div style={{ fontSize: '1.9rem', fontWeight: '800', color: '#34d399', marginTop: '0.5rem' }}>
            {stats?.secrets_redacted ?? 0}
          </div>
          <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.25rem' }}>
            Tokens & credentials sanitized
          </div>
        </div>
      </div>

      {/* Main Section: Incidents Workbench & Architectural Security Posture */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.7fr 1fr', gap: '1.5rem' }}>
        
        {/* Incidents Table */}
        <div className="card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#f8fafc' }}>
                Correlated Incidents
              </h3>
              <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                Grouped by entity, sliding time window, and deterministic alert chains
              </p>
            </div>
            <button 
              className="btn btn-secondary" 
              style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
              onClick={() => onNavigateTab('incidents')}
            >
              View All ({incidents.length}) <ArrowRight size={14} />
            </button>
          </div>

          {incidents.length === 0 ? (
            <div style={{ 
              textAlign: 'center', 
              padding: '3rem 1rem', 
              color: '#94a3b8', 
              border: '1px dashed var(--border-light)',
              borderRadius: '8px'
            }}>
              <ShieldCheck size={36} style={{ color: '#10b981', marginBottom: '0.75rem' }} />
              <p style={{ fontWeight: '600' }}>No active incidents detected yet.</p>
              <p style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '0.25rem' }}>
                Click "Simulate Attack Scenarios" above or ingest new log streams to trigger detection.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {incidents.slice(0, 5).map((inc) => (
                <div 
                  key={inc.incident_id}
                  onClick={() => onSelectIncident(inc)}
                  style={{
                    background: 'rgba(15, 23, 42, 0.6)',
                    border: '1px solid var(--border-light)',
                    borderRadius: '10px',
                    padding: '1rem',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '1rem'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.4)';
                    e.currentTarget.style.transform = 'translateX(3px)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = 'var(--border-light)';
                    e.currentTarget.style.transform = 'none';
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span className="mono" style={{ fontSize: '0.78rem', color: '#38bdf8', fontWeight: '600' }}>
                        {inc.incident_id}
                      </span>
                      <span className={`badge badge-${inc.severity.toLowerCase()}`}>
                        {inc.severity}
                      </span>
                      <span className="badge badge-purple" style={{ fontSize: '0.7rem' }}>
                        {inc.status}
                      </span>
                      {inc.ai_investigation_status === 'COMPLETED' && (
                        <span className="badge badge-verified" style={{ fontSize: '0.68rem' }}>
                          <Sparkles size={11} /> AI Investigated
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.925rem', fontWeight: '600', color: '#f1f5f9' }}>
                      {inc.title}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'flex', gap: '1rem' }}>
                      <span>User: <strong style={{ color: '#e2e8f0' }}>{inc.primary_user || 'N/A'}</strong></span>
                      <span>Target Host: <strong style={{ color: '#e2e8f0' }}>{inc.primary_host || 'N/A'}</strong></span>
                      <span>Events Correlated: <strong style={{ color: '#38bdf8' }}>{inc.event_count}</strong></span>
                    </div>
                  </div>

                  <button className="btn btn-primary" style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem' }}>
                    <Eye size={14} /> Investigate
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Posture & Guardrails Card */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div className="card" style={{ padding: '1.5rem' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: '700', color: '#f8fafc', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldCheck size={18} color="#34d399" /> Operational AI Guardrails
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem', fontSize: '0.825rem' }}>
              <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', borderLeft: '3px solid #10b981' }}>
                <strong style={{ color: '#34d399' }}>1. Zero-Execution Principle</strong>
                <p style={{ color: '#94a3b8', marginTop: '0.2rem' }}>
                  Model is strictly an investigative advisor. No suggested commands are ever executed automatically on infrastructure.
                </p>
              </div>

              <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', borderLeft: '3px solid #00f2fe' }}>
                <strong style={{ color: '#38bdf8' }}>2. Deterministic Verification</strong>
                <p style={{ color: '#94a3b8', marginTop: '0.2rem' }}>
                  LangGraph node verifies every event citation ID against ground truth. Fabricated or hallucinated IDs are explicitly flagged and penalized.
                </p>
              </div>

              <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', borderLeft: '3px solid #f43f5e' }}>
                <strong style={{ color: '#fb7185' }}>3. Untrusted Log Quarantining</strong>
                <p style={{ color: '#94a3b8', marginTop: '0.2rem' }}>
                  Raw logs undergo regex sanitization, secret redaction, and boundary escaping to neutralize prompt injection attacks.
                </p>
              </div>

              <div style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', borderLeft: '3px solid #a855f7' }}>
                <strong style={{ color: '#c084fc' }}>4. 4-Tier Evidence Taxonomy</strong>
                <p style={{ color: '#94a3b8', marginTop: '0.2rem' }}>
                  Clear segregation between Confirmed Evidence [EVIDENCE], Rule Alerts [ALERT], AI Hypotheses [HYPOTHESIS], and Unknowns [UNKNOWN].
                </p>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '600', textTransform: 'uppercase' }}>
              Quick Navigation
            </span>
            <button className="btn btn-secondary" onClick={() => onNavigateTab('logs')} style={{ justifyContent: 'flex-start' }}>
              <Terminal size={15} /> Ingest & Inspect Raw Security Logs
            </button>
            <button className="btn btn-secondary" onClick={() => onNavigateTab('rules')} style={{ justifyContent: 'flex-start' }}>
              <Activity size={15} /> Detection Rules & Threat Watchlists
            </button>
            <button className="btn btn-secondary" onClick={() => onNavigateTab('audit')} style={{ justifyContent: 'flex-start' }}>
              <FileText size={15} /> Immutable Analyst Action Audit Trail
            </button>
          </div>
        </div>

      </div>

    </div>
  );
}
