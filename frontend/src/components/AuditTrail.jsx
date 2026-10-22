import React, { useState, useEffect } from 'react';
import { FileText, Shield, User, Clock, RefreshCw, CheckCircle2, AlertOctagon } from 'lucide-react';
import { fetchAuditLogs } from '../services/api';

export default function AuditTrail({ onSelectIncidentById }) {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterAction, setFilterAction] = useState('');

  const loadAudits = async () => {
    setLoading(true);
    try {
      const data = await fetchAuditLogs();
      setAudits(data.results || data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAudits();
  }, []);

  const filtered = audits.filter(a => filterAction ? a.action_type === filterAction : true);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#f8fafc' }}>
            SOC Analyst Audit Trail & Compliance Log
          </h2>
          <p style={{ fontSize: '0.825rem', color: '#94a3b8' }}>
            Immutable chronological record of all human triage actions, AI investigations, and escalation decisions
          </p>
        </div>

        <button className="btn btn-secondary" onClick={loadAudits} disabled={loading}>
          <RefreshCw size={15} className={loading ? 'spin' : ''} /> Refresh
        </button>
      </div>

      {/* Filter */}
      <div className="card" style={{ padding: '0.85rem 1.25rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: '600' }}>Filter by Action:</span>
        <select 
          className="select" 
          style={{ maxWidth: '240px' }}
          value={filterAction} 
          onChange={(e) => setFilterAction(e.target.value)}
        >
          <option value="">All Analyst Actions</option>
          <option value="CONFIRM_FINDING">Confirm Finding</option>
          <option value="REJECT_FINDING">Reject / False Positive</option>
          <option value="ESCALATE">Escalate to CSIRT</option>
          <option value="RUN_AI_INVESTIGATION">Run AI Investigation</option>
          <option value="RESOLVE">Resolve Incident</option>
        </select>
      </div>

      {/* Audit Log Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
            <thead>
              <tr style={{ background: 'rgba(15, 23, 42, 0.8)', borderBottom: '1px solid var(--border-light)' }}>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Timestamp (UTC)</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Analyst</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Action Taken</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Status Transition</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Analyst Notes & Rationale</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
                    {loading ? 'Loading audit entries...' : 'No audit trail records found.'}
                  </td>
                </tr>
              ) : (
                filtered.map((item) => (
                  <tr key={item.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '0.8rem 1rem', whiteSpace: 'nowrap' }}>
                      <span className="mono" style={{ color: '#94a3b8' }}>
                        {new Date(item.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                      </span>
                    </td>
                    <td style={{ padding: '0.8rem 1rem', color: '#f8fafc', fontWeight: '600' }}>
                      👤 {item.analyst_name}
                    </td>
                    <td style={{ padding: '0.8rem 1rem' }}>
                      <span className={`badge ${
                        item.action_type === 'CONFIRM_FINDING' ? 'badge-verified' :
                        item.action_type === 'ESCALATE' ? 'badge-critical' :
                        item.action_type === 'RUN_AI_INVESTIGATION' ? 'badge-purple' : 'badge-medium'
                      }`}>
                        {item.action_type}
                      </span>
                    </td>
                    <td style={{ padding: '0.8rem 1rem', color: '#cbd5e1' }}>
                      {item.previous_status || 'INIT'} ➔ <strong style={{ color: '#38bdf8' }}>{item.new_status}</strong>
                    </td>
                    <td style={{ padding: '0.8rem 1rem', color: '#e2e8f0' }}>
                      {item.notes || <span style={{ color: '#64748b', fontStyle: 'italic' }}>Automated system record</span>}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
