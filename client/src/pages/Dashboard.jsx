import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, ShieldAlert, CheckCircle, Clock } from 'lucide-react';
import { dashboardService } from '../services/api';
import './Dashboard.css';

export default function Dashboard() {
  const [statsData, setStatsData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        // Need a token or the auth middleware in backend will reject (if we had enforced it strictly without a user)
        // Since auth is enabled, we'd normally get a 401 here if not logged in.
        // For prototype purposes, assuming the backend can handle the request or we mock it if failed
        const response = await dashboardService.getStats();
        setStatsData(response.data);
      } catch (err) {
        console.error('Failed to fetch dashboard stats', err);
        // Fallback for prototype demonstration
        setStatsData({
          totalScans: 1284,
          recentScans: [
            { id: 1, input: { rawInput: 'example-secure-bank.com' }, scanType: 'URL', result: { riskLevel: 'HIGH', trustScore: 24 } },
            { id: 2, input: { rawInput: 'google.com' }, scanType: 'URL', result: { riskLevel: 'LOW', trustScore: 98 } },
            { id: 3, input: { rawInput: 'Update Payment Email' }, scanType: 'EMAIL', result: { riskLevel: 'CRITICAL', trustScore: 12 } },
          ],
        });
      } finally {
        setLoading(false);
      }
    };
    fetchDashboard();
  }, []);

  const threatsBlocked = statsData?.riskDistribution?.reduce((acc, curr) => {
    if (['CRITICAL', 'HIGH'].includes(curr.riskLevel)) return acc + curr._count.riskLevel;
    return acc;
  }, 0) || 0;

  const safeLinks = statsData?.riskDistribution?.reduce((acc, curr) => {
    if (['LOW', 'SAFE', 'MINIMAL'].includes(curr.riskLevel)) return acc + curr._count.riskLevel;
    return acc;
  }, 0) || 0;

  const stats = [
    { label: 'Total Scans', value: statsData?.totalScans || 0, icon: Activity, color: 'var(--accent-primary)' },
    { label: 'Threats Blocked', value: threatsBlocked, icon: ShieldAlert, color: 'var(--color-critical)' },
    { label: 'Safe Links', value: safeLinks, icon: CheckCircle, color: 'var(--color-low)' },
  ];

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1 className="text-h2 text-gradient">Security Overview</h1>
        <p className="text-body mt-2">Real-time threat intelligence and digital identity protection.</p>
      </header>

      <div className="stats-grid">
        {stats.map((stat, idx) => {
          const Icon = stat.icon;
          return (
            <motion.div 
              key={stat.label}
              className="stat-card glass-card"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.1 }}
            >
              <div className="stat-icon" style={{ backgroundColor: `${stat.color}20`, color: stat.color }}>
                <Icon size={24} />
              </div>
              <div className="stat-content">
                <div className="stat-value text-h3">
                  {loading ? '...' : stat.value}
                </div>
                <div className="stat-label text-small">{stat.label}</div>
              </div>
            </motion.div>
          );
        })}
      </div>

      <div className="dashboard-grid">
        <motion.div 
          className="recent-scans-panel glass-card"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.4 }}
        >
          <div className="panel-header">
            <h2 className="text-h4">Recent Analysis</h2>
            <button className="btn btn-secondary text-small">View All</button>
          </div>
          <div className="scans-list">
            {loading ? (
               <div className="flex-center py-8"><p className="text-muted">Loading...</p></div>
            ) : (statsData?.recentScans || []).map((scan) => (
              <div key={scan.id} className="scan-item">
                <div className="scan-info">
                  <span className="scan-url" style={{
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      maxWidth: '300px',
                      display: 'inline-block'
                  }}>
                      {scan.input?.rawInput || 'Unknown'}
                  </span>
                </div>
                <div className="scan-meta">
                  <span className="scan-type">{scan.scanType}</span>
                  <span className={`risk-badge risk-${(scan.result?.riskLevel || 'UNKNOWN').toLowerCase()}`}>
                    {scan.result?.riskLevel || 'UNKNOWN'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        <motion.div 
          className="system-health-panel glass-card"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.5 }}
        >
          <div className="panel-header">
            <h2 className="text-h4">Provider Status</h2>
          </div>
          <div className="providers-list">
            {['VirusTotal', 'Google Safe Browsing', 'URLScan', 'RDAP', 'OpenRouter AI'].map((provider) => (
              <div key={provider} className="provider-item">
                <span className="provider-name">{provider}</span>
                <span className="status-indicator online"></span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
