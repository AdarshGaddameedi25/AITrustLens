import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Fingerprint,
  Mail,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Server,
  Key,
  Globe,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Loader,
  ExternalLink,
} from 'lucide-react';
import { analyzeService } from '../services/api';
import './Analysis.css';

export default function IdentityAnalysis() {
  const [email, setEmail] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!email) return;

    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeService.identity(email);
      setResult(response.data);
    } catch (err) {
      setError(err.error?.message || 'Failed to analyze digital identity. Please verify the email address.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'var(--color-critical)';
      case 'HIGH': return 'var(--color-high)';
      case 'MODERATE': return 'var(--color-moderate)';
      case 'LOW': return 'var(--color-low)';
      case 'HIGH_TRUST': return 'var(--color-trust)';
      default: return 'var(--text-muted)';
    }
  };

  const getStatusBadge = (status) => {
    if (status === 'VERIFIED') {
      return <span className="badge badge-success flex-center gap-1" style={{ fontSize: '0.75rem', padding: '0.2rem 0.6rem' }}><CheckCircle size={12} /> Verified</span>;
    }
    if (status === 'USER_PROVIDED') {
      return <span className="badge badge-info flex-center gap-1" style={{ fontSize: '0.75rem', padding: '0.2rem 0.6rem' }}><HelpCircle size={12} /> Provided</span>;
    }
    return <span className="badge badge-warning flex-center gap-1" style={{ fontSize: '0.75rem', padding: '0.2rem 0.6rem' }}><AlertTriangle size={12} /> Unavailable</span>;
  };

  return (
    <div className="analysis-container">
      <header className="analysis-header">
        <h1 className="text-h2 text-gradient">Digital Identity Exposure & Domain Security</h1>
        <p className="text-body mt-2">
          Verify email identity authenticity, DNS mail exchangers (MX), SPF / DMARC authentication, and disposable domain exposure.
          <br />
          <span className="text-small text-muted mt-1 inline-block">
            <Shield size={12} className="inline mr-1" />
            Deterministic DNS verification. All evidence strictly classified as Verified or Unavailable.
          </span>
        </p>
      </header>

      <motion.div
        className="glass-card analysis-input-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <form onSubmit={handleAnalyze} className="analysis-form">
          <div className="input-wrapper">
            <Mail className="input-icon" size={20} />
            <input
              type="email"
              placeholder="Enter email address (e.g., user@company.com or john@gmail.com)"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={isAnalyzing}
              required
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={isAnalyzing || !email}
          >
            {isAnalyzing ? (
              <>
                <Loader className="spin" size={18} />
                <span>Auditing Identity...</span>
              </>
            ) : (
              <>
                <Fingerprint size={18} />
                <span>Analyze Identity</span>
              </>
            )}
          </button>
        </form>

        {error && (
          <motion.div
            className="error-message mt-4 flex items-center gap-2 text-danger"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <AlertTriangle size={18} />
            <span>{error}</span>
          </motion.div>
        )}
      </motion.div>

      {/* Results Section */}
      {result && (
        <motion.div
          className="results-container"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          {/* Trust Score & Overview Card */}
          <div className="glass-card result-score-card">
            <div className="score-display">
              <div
                className="score-circle"
                style={{
                  background: `conic-gradient(${getRiskColor(result.riskLevel)} ${result.trustScore}%, var(--bg-surface) 0)`,
                }}
              >
                <div className="score-inner">
                  <span className="score-value" style={{ color: getRiskColor(result.riskLevel) }}>
                    {result.trustScore}
                  </span>
                  <span className="score-label">Trust Score</span>
                </div>
              </div>

              <div className="score-meta">
                <div className="meta-badge-group">
                  <span
                    className="risk-badge"
                    style={{
                      backgroundColor: `${getRiskColor(result.riskLevel)}20`,
                      color: getRiskColor(result.riskLevel),
                      borderColor: getRiskColor(result.riskLevel),
                    }}
                  >
                    {result.riskLevel}
                  </span>
                  <span className="confidence-badge">
                    Confidence: <strong>{result.confidence}</strong>
                  </span>
                  <span className="coverage-badge">
                    Coverage: <strong>{result.evidenceCoverage}%</strong>
                  </span>
                </div>

                <h3 className="target-title mt-2">
                  <Fingerprint size={18} className="inline mr-2 text-primary" />
                  {result.email}
                </h3>
                <p className="text-small text-muted">
                  Domain: <strong>{result.domain}</strong> • Completed: {new Date(result.completedAt).toLocaleTimeString()}
                </p>
              </div>
            </div>

            {/* AI Summary */}
            {result.aiExplanation?.summary && (
              <div className="ai-summary-box glass-panel mt-4">
                <div className="flex items-center gap-2 mb-2 text-accent">
                  <ShieldCheck size={18} />
                  <h4 className="font-semibold text-small">Identity Security Assessment</h4>
                </div>
                <p className="text-body text-secondary">{result.aiExplanation.summary}</p>
                {result.aiExplanation.riskExplanation && (
                  <p className="text-small text-muted mt-2">{result.aiExplanation.riskExplanation}</p>
                )}
              </div>
            )}
          </div>

          {/* Evidence Breakdown Grid */}
          <h3 className="section-heading mt-6 mb-3 text-gradient">
            <Server size={20} className="inline mr-2" />
            Verified Evidence & DNS Posture
          </h3>

          <div className="evidence-grid">
            {result.evidence?.items?.map((item, idx) => (
              <div key={idx} className="glass-card evidence-card">
                <div className="flex justify-between items-start mb-2">
                  <span className="evidence-source text-muted text-tiny">{item.source}</span>
                  {getStatusBadge(item.status)}
                </div>
                <h4 className="evidence-indicator font-semibold text-small mb-1">
                  {item.indicator.replace(/_/g, ' ')}
                </h4>

                {item.status === 'VERIFIED' ? (
                  <div className="evidence-details text-small text-secondary">
                    {item.indicator === 'DNS_MX_RECORDS' && (
                      <p>
                        MX Records: <strong>{item.value?.hasMx ? `${item.value.recordCount} Active Exchanger(s)` : 'None (Unroutable)'}</strong>
                        {item.value?.exchanges?.length > 0 && (
                          <span className="block text-tiny text-muted mt-1 truncate">
                            Host: {item.value.exchanges[0]}
                          </span>
                        )}
                      </p>
                    )}
                    {item.indicator === 'DNS_SPF_RECORD' && (
                      <p>
                        SPF Record: <strong>{item.value?.hasSpf ? 'Configured' : 'Missing'}</strong>
                        {item.value?.record && (
                          <span className="block text-tiny text-muted mt-1 truncate">
                            Policy: {item.value.record}
                          </span>
                        )}
                      </p>
                    )}
                    {item.indicator === 'DNS_DMARC_RECORD' && (
                      <p>
                        DMARC Policy: <strong>{item.value?.hasDmarc ? `Policy: ${item.value.policy}` : 'Missing'}</strong>
                      </p>
                    )}
                    {item.indicator === 'DOMAIN_CLASSIFICATION' && (
                      <p>
                        Classification: <strong>{item.value?.isDisposable ? 'Disposable / Temp Mail' : item.value?.isFreeProvider ? 'Public Webmail' : 'Custom / Corporate Domain'}</strong>
                      </p>
                    )}
                    {item.indicator === 'EMAIL_FORMAT_VALIDITY' && (
                      <p>Syntax Check: <strong>RFC-Compliant Email Structure</strong></p>
                    )}
                  </div>
                ) : (
                  <p className="text-small text-muted italic">
                    {item.reason || 'Source unavailable during this scan'}
                  </p>
                )}
              </div>
            ))}
          </div>

          {/* Actionable Recommendations */}
          {result.recommendations?.length > 0 && (
            <div className="recommendations-section mt-6">
              <h3 className="section-heading mb-3 text-gradient">
                <Key size={20} className="inline mr-2" />
                Actionable Identity Safeguards
              </h3>
              <div className="recommendations-list">
                {result.recommendations.map((rec, idx) => (
                  <div key={idx} className="glass-card recommendation-card">
                    <div className="rec-header">
                      <span className={`priority-tag priority-${rec.priority.toLowerCase()}`}>
                        {rec.priority}
                      </span>
                      <span className="rec-category text-muted text-tiny">{rec.category}</span>
                    </div>
                    <h4 className="rec-title font-semibold mt-1">{rec.title}</h4>
                    <p className="rec-detail text-small text-secondary mt-1">{rec.detail}</p>
                    {rec.action && (
                      <div className="rec-action glass-panel mt-2 p-2 text-small">
                        <strong>Recommended Action:</strong> {rec.action}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
}
