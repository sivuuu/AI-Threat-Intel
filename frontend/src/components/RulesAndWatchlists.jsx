import React, { useState, useEffect } from 'react';
import { 
  Activity, Shield, Plus, ToggleLeft, ToggleRight, 
  AlertTriangle, RefreshCw, Check, Globe, UserX, Hash, Lock
} from 'lucide-react';
import { 
  fetchDetectionRules, updateDetectionRule, 
  fetchWatchlists, createWatchlist 
} from '../services/api';

export default function RulesAndWatchlists() {
  const [rules, setRules] = useState([]);
  const [watchlists, setWatchlists] = useState([]);
  const [loading, setLoading] = useState(true);

  // New Watchlist Form
  const [showAddWl, setShowAddWl] = useState(false);
  const [wlType, setWlType] = useState('IP');
  const [wlValue, setWlValue] = useState('');
  const [wlActor, setWlActor] = useState('');
  const [wlCategory, setWlCategory] = useState('C2_INFRASTRUCTURE');
  const [wlSeverity, setWlSeverity] = useState('HIGH');
  const [wlConfidence, setWlConfidence] = useState(90);
  const [submittingWl, setSubmittingWl] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [rData, wData] = await Promise.all([
        fetchDetectionRules(),
        fetchWatchlists(),
      ]);
      setRules(rData.results || rData || []);
      setWatchlists(wData.results || wData || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleRule = async (rule) => {
    try {
      await updateDetectionRule(rule.id, { is_active: !rule.is_active });
      loadData();
    } catch (err) {
      alert('Failed to toggle rule: ' + err.message);
    }
  };

  const handleAddWatchlist = async (e) => {
    e.preventDefault();
    if (!wlValue.trim()) return;
    setSubmittingWl(true);
    try {
      await createWatchlist({
        watch_type: wlType,
        value: wlValue.trim(),
        threat_actor: wlActor.trim() || 'Suspect Actor',
        category: wlCategory,
        severity: wlSeverity,
        confidence: parseInt(wlConfidence, 10),
      });
      setShowAddWl(false);
      setWlValue('');
      setWlActor('');
      loadData();
    } catch (err) {
      alert('Failed to add watchlist IOC: ' + err.message);
    } finally {
      setSubmittingWl(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#f8fafc' }}>
          Detection Rules & Threat Intelligence Watchlists
        </h2>
        <p style={{ fontSize: '0.825rem', color: '#94a3b8' }}>
          Deterministic pattern matching engines and high-fidelity indicators of compromise (IOCs)
        </p>
      </div>

      {/* Rules Section */}
      <div className="card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Activity size={18} color="#38bdf8" /> Active Detection Rules
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              Deterministic signatures evaluated on ingestion before AI investigation
            </p>
          </div>
          <button className="btn btn-secondary" onClick={loadData} disabled={loading} style={{ fontSize: '0.8rem' }}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
          {rules.map((rule) => (
            <div 
              key={rule.rule_id}
              style={{
                background: 'rgba(15, 23, 42, 0.6)',
                border: '1px solid var(--border-light)',
                borderRadius: '10px',
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '0.75rem'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <span className="mono" style={{ fontSize: '0.75rem', color: '#38bdf8', fontWeight: '600' }}>
                    {rule.rule_id}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span className={`badge badge-${rule.severity.toLowerCase()}`} style={{ fontSize: '0.68rem' }}>
                      {rule.severity}
                    </span>
                    <button 
                      onClick={() => handleToggleRule(rule)}
                      style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: rule.is_active ? '#34d399' : '#64748b' }}
                      title={rule.is_active ? 'Disable rule' : 'Enable rule'}
                    >
                      {rule.is_active ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
                    </button>
                  </div>
                </div>

                <h4 style={{ fontSize: '0.925rem', fontWeight: '700', color: '#f1f5f9', marginBottom: '0.35rem' }}>
                  {rule.name}
                </h4>
                <p style={{ fontSize: '0.8rem', color: '#cbd5e1', lineHeight: '1.4' }}>
                  {rule.description}
                </p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '0.75rem', fontSize: '0.75rem', color: '#94a3b8' }}>
                <span>Window: <strong style={{ color: '#e2e8f0' }}>{rule.time_window_minutes}m</strong></span>
                <span>Threshold: <strong style={{ color: '#e2e8f0' }}>{rule.threshold} evts</strong></span>
                {rule.mitre_attack_id && (
                  <span className="mono" style={{ color: '#c084fc' }}>MITRE {rule.mitre_attack_id}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Threat Watchlists Section */}
      <div className="card" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={18} color="#10b981" /> Threat Intelligence Watchlists (IOCs)
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              Monitored malicious IPs, deception honey-tokens, and suspect infrastructure
            </p>
          </div>
          <button 
            className="btn btn-primary"
            onClick={() => setShowAddWl(!showAddWl)}
            style={{ fontSize: '0.8rem' }}
          >
            <Plus size={15} /> Add Watchlist IOC
          </button>
        </div>

        {/* Add Watchlist Form */}
        {showAddWl && (
          <form onSubmit={handleAddWatchlist} style={{ padding: '1.25rem', background: 'rgba(8, 12, 22, 0.8)', border: '1px solid var(--border-light)', borderRadius: '10px', marginBottom: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <h4 style={{ fontSize: '0.9rem', fontWeight: '700', color: '#f8fafc' }}>
              Add New Threat Watchlist Entry
            </h4>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.3rem' }}>IOC Type</label>
                <select className="select" value={wlType} onChange={(e) => setWlType(e.target.value)}>
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain Name</option>
                  <option value="USERNAME">Target / Honey Username</option>
                  <option value="HASH">File Hash (SHA256)</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.3rem' }}>IOC Value</label>
                <input 
                  type="text" 
                  className="input mono" 
                  placeholder="e.g. 198.51.100.44 or admin_honey"
                  value={wlValue}
                  onChange={(e) => setWlValue(e.target.value)}
                  required
                />
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.3rem' }}>Threat Actor / Attribution</label>
                <input 
                  type="text" 
                  className="input" 
                  placeholder="e.g. APT-29 / Deception Token"
                  value={wlActor}
                  onChange={(e) => setWlActor(e.target.value)}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.3rem' }}>Severity</label>
                <select className="select" value={wlSeverity} onChange={(e) => setWlSeverity(e.target.value)}>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowAddWl(false)}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={submittingWl}>
                {submittingWl ? 'Adding...' : 'Save Watchlist Entry'}
              </button>
            </div>
          </form>
        )}

        {/* Watchlist Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
            <thead>
              <tr style={{ background: 'rgba(15, 23, 42, 0.8)', borderBottom: '1px solid var(--border-light)' }}>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Type</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>IOC Value</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Threat Attribution</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Category</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Severity</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Confidence</th>
                <th style={{ padding: '0.85rem 1rem', color: '#94a3b8', fontWeight: '600' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {watchlists.map((wl) => (
                <tr key={wl.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                  <td style={{ padding: '0.8rem 1rem' }}>
                    <span className="badge badge-purple" style={{ fontSize: '0.7rem' }}>
                      {wl.watch_type}
                    </span>
                  </td>
                  <td style={{ padding: '0.8rem 1rem' }}>
                    <span className="mono" style={{ color: '#38bdf8', fontWeight: '700' }}>
                      {wl.value}
                    </span>
                  </td>
                  <td style={{ padding: '0.8rem 1rem', color: '#f1f5f9', fontWeight: '500' }}>
                    {wl.threat_actor || 'Unknown Actor'}
                  </td>
                  <td style={{ padding: '0.8rem 1rem', color: '#cbd5e1' }}>
                    {wl.category}
                  </td>
                  <td style={{ padding: '0.8rem 1rem' }}>
                    <span className={`badge badge-${wl.severity.toLowerCase()}`}>
                      {wl.severity}
                    </span>
                  </td>
                  <td style={{ padding: '0.8rem 1rem' }}>
                    <span style={{ color: wl.confidence >= 90 ? '#34d399' : '#fbbf24', fontWeight: '600' }}>
                      {wl.confidence}%
                    </span>
                  </td>
                  <td style={{ padding: '0.8rem 1rem' }}>
                    <span className="badge badge-verified" style={{ fontSize: '0.68rem' }}>
                      <Check size={11} /> Monitored
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
