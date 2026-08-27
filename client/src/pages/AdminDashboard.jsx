import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Users, Activity, TrendingUp, CheckCircle, Clock, AlertTriangle, XCircle } from 'lucide-react';
import './AdminDashboard.css';

const API = import.meta.env.VITE_API_URL || '/api';

const STATUS_ICON = {
  COMPLETED: <CheckCircle size={14} className="text-safe" />,
  PROCESSING: <Clock size={14} className="text-warn" />,
  QUEUED:     <Clock size={14} className="text-muted" />,
  FAILED:     <XCircle size={14} className="text-danger" />,
};

function getRiskColor(level) {
  return { CRITICAL:'#ef4444', HIGH:'#f97316', MODERATE:'#eab308', LOW:'#22c55e', HIGH_TRUST:'#10b981' }[level] || '#6b7280';
}

export default function AdminDashboard() {
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const pageSize = 20;

  const authHeader = () => ({ Authorization: `Bearer ${localStorage.getItem('token')}` });

  useEffect(() => {
    Promise.all([
      fetch(`${API}/admin/stats`, { headers: authHeader() }).then(r => r.json()),
      fetch(`${API}/admin/scans?page=${page}${filter ? `&status=${filter}` : ''}`, { headers: authHeader() }).then(r => r.json()),
    ]).then(([statsRes, scansRes]) => {
      setStats(statsRes.data);
      setScans(scansRes.data?.scans || []);
      setTotal(scansRes.data?.total || 0);
    }).catch(console.error).finally(() => setLoading(false));
  }, [page, filter]);

  if (loading) {
    return (
      <div className="admin-loading">
        <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
          <Shield size={40} style={{ color: 'var(--accent-primary)' }} />
        </motion.div>
        <p>Loading admin dashboard...</p>
      </div>
    );
  }

  return (
    <div className="admin-container">
      <header className="admin-header">
        <h1 className="text-h2 text-gradient">Admin Dashboard</h1>
        <p className="text-body mt-1" style={{ color: 'var(--text-muted)' }}>Platform-wide scan monitoring &amp; analytics</p>
      </header>

      {/* Stats Cards */}
      {stats && (
        <div className="admin-stats-grid">
          {[
            { label: 'Total Scans', value: stats.totalScans, icon: <Activity size={24} />, color: 'var(--accent-primary)' },
            { label: 'Completed', value: stats.byStatus?.COMPLETED || 0, icon: <CheckCircle size={24} />, color: '#22c55e' },
            { label: 'Failed', value: stats.byStatus?.FAILED || 0, icon: <XCircle size={24} />, color: '#ef4444' },
            { label: 'Avg Trust Score', value: `${stats.averageTrustScore}/100`, icon: <TrendingUp size={24} />, color: '#10b981' },
          ].map((s, i) => (
            <motion.div key={s.label} className="admin-stat-card glass-card"
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.07 }}>
              <div className="stat-icon" style={{ color: s.color }}>{s.icon}</div>
              <div className="stat-value">{s.value}</div>
              <div className="stat-label">{s.label}</div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Filter Bar */}
      <div className="admin-filter-bar glass-card">
        <label className="text-small" style={{ color: 'var(--text-muted)' }}>Filter by status:</label>
        {['', 'COMPLETED', 'PROCESSING', 'QUEUED', 'FAILED'].map(s => (
          <button key={s || 'all'} className={`filter-btn ${filter === s ? 'active' : ''}`}
            onClick={() => { setFilter(s); setPage(1); }}>
            {s || 'All'}
          </button>
        ))}
      </div>

      {/* Scans Table */}
      <motion.div className="admin-table-card glass-card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <table className="admin-table">
          <thead>
            <tr>
              <th>URL</th><th>User</th><th>Status</th><th>Trust Score</th><th>Risk Level</th><th>Created</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>No scans found.</td></tr>
            )}
            {scans.map(scan => (
              <tr key={scan.id}>
                <td className="url-cell" title={scan.url}>{scan.url ? scan.url.substring(0, 50) + (scan.url.length > 50 ? '…' : '') : 'N/A'}</td>
                <td>{scan.user?.email || '—'}</td>
                <td><span className="status-cell">{STATUS_ICON[scan.status]}{scan.status}</span></td>
                <td>{scan.result?.trustScore ?? '—'}</td>
                <td><span style={{ color: getRiskColor(scan.result?.riskLevel), fontWeight: 600 }}>{scan.result?.riskLevel || '—'}</span></td>
                <td>{new Date(scan.createdAt).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="admin-pagination">
          <button className="btn btn-secondary btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span className="text-small" style={{ color: 'var(--text-muted)' }}>Page {page} of {Math.ceil(total / pageSize) || 1}</span>
          <button className="btn btn-secondary btn-sm" disabled={page >= Math.ceil(total / pageSize)} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      </motion.div>
    </div>
  );
}
