import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Activity, Terminal, Eye, FileText, 
  Layers, Lock, Cpu, Play, Bell, AlertOctagon, CheckCircle2 
} from 'lucide-react';

import Dashboard from './components/Dashboard';
import IncidentView from './components/IncidentView';
import LogStream from './components/LogStream';
import RulesAndWatchlists from './components/RulesAndWatchlists';
import AuditTrail from './components/AuditTrail';
import { fetchDashboardStats, fetchIncidents, seedSampleScenarios } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [loadingSeed, setLoadingSeed] = useState(false);
  const [notification, setNotification] = useState('');

  const loadData = async () => {
    try {
      const [sData, incData] = await Promise.all([
        fetchDashboardStats(),
        fetchIncidents(),
      ]);
      setStats(sData);
      setIncidents(incData.results || incData || []);
    } catch (err) {
      console.error('Failed to load global data:', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 20000);
    return () => clearInterval(interval);
  }, []);

  const handleSeedScenarios = async () => {
    setLoadingSeed(true);
    try {
      const resp = await seedSampleScenarios();
      setNotification(`Attacks simulated: ${resp.logs_created} logs ingested, ${resp.alerts_triggered} alerts triggered, ${resp.incidents_created} incident correlated.`);
      await loadData();
      setTimeout(() => setNotification(''), 4500);
    } catch (err) {
      alert('Failed to simulate scenarios: ' + err.message);
    } finally {
      setLoadingSeed(false);
    }
  };

  const handleSelectIncident = (inc) => {
    setSelectedIncidentId(inc.incident_id);
    setActiveTab('incidents');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* Top SOC App Header */}
      <header style={{
        background: 'rgba(7, 11, 19, 0.95)',
        backdropFilter: 'blur(16px)',
        borderBottom: '1px solid var(--border-light)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        padding: '0.75rem 2rem'
      }}>
        <div style={{ 
          maxWidth: '1600px', 
          margin: '0 auto', 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          flexWrap: 'wrap', 
          gap: '1rem' 
        }}>
          
          {/* Logo & Brand */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <div style={{ 
              width: '40px', 
              height: '40px', 
              borderRadius: '10px', 
              background: 'linear-gradient(135deg, #0284c7 0%, #7c3aed 100%)',
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              boxShadow: '0 0 15px rgba(2, 132, 199, 0.4)'
            }}>
              <ShieldAlert size={22} color="#ffffff" />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1.15rem', fontWeight: '800', letterSpacing: '-0.02em', color: '#f8fafc' }}>
                  AEGIS-HUNT
                </span>
                <span className="badge badge-low" style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem' }}>
                  SOC TIER-2/3
                </span>
              </div>
              <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                AI-Assisted Threat Hunting & Incident Investigation System
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav style={{ display: 'flex', gap: '0.4rem', background: '#090e1a', padding: '0.3rem', borderRadius: '10px', border: '1px solid var(--border-light)' }}>
            <button 
              className={`btn ${activeTab === 'dashboard' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem', border: 'none' }}
              onClick={() => { setActiveTab('dashboard'); setSelectedIncidentId(null); }}
            >
              <Activity size={15} /> Dashboard
            </button>
            <button 
              className={`btn ${activeTab === 'incidents' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem', border: 'none' }}
              onClick={() => {
                setActiveTab('incidents');
                if (!selectedIncidentId && incidents.length > 0) {
                  setSelectedIncidentId(incidents[0].incident_id);
                }
              }}
            >
              <ShieldAlert size={15} /> Incidents & Investigation
            </button>
            <button 
              className={`btn ${activeTab === 'logs' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem', border: 'none' }}
              onClick={() => setActiveTab('logs')}
            >
              <Terminal size={15} /> Logs & Ingestion
            </button>
            <button 
              className={`btn ${activeTab === 'rules' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem', border: 'none' }}
              onClick={() => setActiveTab('rules')}
            >
              <Layers size={15} /> Detection Rules & Watchlists
            </button>
            <button 
              className={`btn ${activeTab === 'audit' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem', border: 'none' }}
              onClick={() => setActiveTab('audit')}
            >
              <FileText size={15} /> Audit Trail
            </button>
          </nav>

          {/* Local Status Indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.8rem' }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '0.4rem', 
              padding: '0.35rem 0.75rem', 
              background: 'rgba(16, 185, 129, 0.1)', 
              borderRadius: '9999px',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              color: '#34d399',
              fontWeight: '600'
            }}>
              <span className="status-dot active"></span>
              <span>Ollama {stats?.llm_status?.configured_model || 'qwen3:8b'}</span>
            </div>
          </div>

        </div>
      </header>

      {/* Global Notification Banner */}
      {notification && (
        <div style={{ 
          background: 'linear-gradient(90deg, #0369a1 0%, #4338ca 100%)', 
          color: '#ffffff', 
          padding: '0.65rem 2rem', 
          fontSize: '0.85rem', 
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '0.5rem',
          boxShadow: '0 4px 12px rgba(0,0,0,0.3)'
        }}>
          <CheckCircle2 size={16} /> {notification}
        </div>
      )}

      {/* Main Content Area */}
      <main style={{ maxWidth: '1600px', width: '100%', margin: '0 auto', padding: '2rem', flex: '1' }}>
        
        {activeTab === 'dashboard' && (
          <Dashboard 
            stats={stats}
            incidents={incidents}
            onSelectIncident={handleSelectIncident}
            onSeedScenarios={handleSeedScenarios}
            loadingSeed={loadingSeed}
            onNavigateTab={setActiveTab}
          />
        )}

        {activeTab === 'incidents' && (
          selectedIncidentId ? (
            <IncidentView 
              incidentId={selectedIncidentId}
              onBack={() => {
                if (incidents.length > 1) {
                  // Switch to incidents list selection
                  setSelectedIncidentId(null);
                } else {
                  setActiveTab('dashboard');
                }
              }}
              onStatusUpdated={loadData}
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: '700', color: '#f8fafc' }}>
                    Incident Investigation Queue
                  </h2>
                  <p style={{ fontSize: '0.825rem', color: '#94a3b8' }}>
                    Select an incident to view correlated timeline and run bounded AI investigation
                  </p>
                </div>
                <button 
                  className="btn btn-primary"
                  onClick={handleSeedScenarios}
                  disabled={loadingSeed}
                >
                  <Play size={15} />
                  {loadingSeed ? 'Simulating...' : 'Simulate Attack Scenarios'}
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '1.25rem' }}>
                {incidents.map((inc) => (
                  <div 
                    key={inc.incident_id}
                    className="card"
                    style={{ 
                      padding: '1.25rem', 
                      cursor: 'pointer', 
                      display: 'flex', 
                      flexDirection: 'column', 
                      justifyContent: 'space-between',
                      gap: '1rem',
                      borderLeft: `4px solid ${
                        inc.severity === 'CRITICAL' ? '#f43f5e' :
                        inc.severity === 'HIGH' ? '#f97316' : '#38bdf8'
                      }`
                    }}
                    onClick={() => setSelectedIncidentId(inc.incident_id)}
                  >
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                        <span className="mono" style={{ fontSize: '0.78rem', color: '#38bdf8', fontWeight: '700' }}>
                          {inc.incident_id}
                        </span>
                        <div style={{ display: 'flex', gap: '0.35rem' }}>
                          <span className={`badge badge-${inc.severity.toLowerCase()}`} style={{ fontSize: '0.68rem' }}>
                            {inc.severity}
                          </span>
                          <span className="badge badge-purple" style={{ fontSize: '0.68rem' }}>
                            {inc.status}
                          </span>
                        </div>
                      </div>

                      <h3 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#f1f5f9', marginBottom: '0.4rem' }}>
                        {inc.title}
                      </h3>

                      <div style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                        <div>User: <strong style={{ color: '#e2e8f0' }}>{inc.primary_user || 'N/A'}</strong></div>
                        <div>Target Host: <strong style={{ color: '#e2e8f0' }}>{inc.primary_host || 'N/A'}</strong></div>
                        <div>Source IP: <strong className="mono" style={{ color: '#38bdf8' }}>{inc.primary_ip || 'Internal'}</strong></div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '0.75rem' }}>
                      <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                        {inc.event_count} events correlated
                      </span>
                      <button className="btn btn-primary" style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}>
                        <Eye size={13} /> Open Investigation
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )
        )}

        {activeTab === 'logs' && (
          <LogStream onLogIngested={loadData} />
        )}

        {activeTab === 'rules' && (
          <RulesAndWatchlists />
        )}

        {activeTab === 'audit' && (
          <AuditTrail />
        )}

      </main>

      {/* Footer */}
      <footer style={{ 
        borderTop: '1px solid var(--border-light)', 
        padding: '1.25rem 2rem', 
        fontSize: '0.8rem', 
        color: '#64748b',
        background: '#04070d'
      }}>
        <div style={{ maxWidth: '1600px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <strong>AI-Assisted Threat Hunting & Incident Investigation System</strong> • Bounded LangGraph Workflow
          </div>
          <div>
            Security Principle: AI Assists Analysts • Human Approval Enforced For All Containment Actions
          </div>
        </div>
      </footer>

    </div>
  );
}
