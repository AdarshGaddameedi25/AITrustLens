import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Link as LinkIcon, Loader, AlertTriangle, ShieldCheck,
  CheckCircle, Info, Clock, Zap, Radio, Database, Brain
} from 'lucide-react';
import { analyzeService } from '../services/api';
import { openScanStream } from '../services/scanStream';
import { sanitize } from '../utils/sanitize';
import './Analysis.css';

const STAGE_CONFIG = {
  EVIDENCE_COLLECTION: { icon: Database, label: 'Querying intelligence providers...' },
  RISK_ENGINE:         { icon: Zap,      label: 'Running deterministic risk engine...' },
  AI_EXPLANATION:      { icon: Brain,    label: 'Generating AI explanation...' },
  COMPLETE:            { icon: CheckCircle, label: 'Analysis complete!' },
};

export default function UrlAnalysis() {
  const [url, setUrl] = useState('');
  const [scanState, setScanState] = useState('idle'); // idle | queued | processing | complete | error
  const [progress, setProgress] = useState(0);
  const [stageMessage, setStageMessage] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const closeStreamRef = useRef(null);

  // Cleanup SSE stream on unmount
  useEffect(() => {
    return () => {
      if (closeStreamRef.current) closeStreamRef.current();
    };
  }, []);

  const startSseStream = (scanId) => {
    const token = localStorage.getItem('token');

    closeStreamRef.current = openScanStream(scanId, token, {
      onProgress: ({ stage, progress: p, message }) => {
        setScanState('processing');
        setProgress(p ?? 0);
        setStageMessage(message || STAGE_CONFIG[stage]?.label || 'Processing...');
      },
      onComplete: ({ result: scanResult }) => {
        closeStreamRef.current = null;
        setResult(scanResult);
        setScanState('complete');
        setProgress(100);
        setStageMessage('');
      },
      onError: (msg) => {
        closeStreamRef.current = null;
        setError(msg || 'Scan failed. Please try again.');
        setScanState('error');
      },
    });
  };

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!url) return;

    // Close any existing SSE stream
    if (closeStreamRef.current) {
      closeStreamRef.current();
      closeStreamRef.current = null;
    }

    setScanState('queued');
    setProgress(5);
    setStageMessage('Queuing scan...');
    setError(null);
    setResult(null);

    try {
      const response = await analyzeService.url({ url });
      const data = response.data ?? response;

      // Cached result — already complete, no SSE needed
      if (data.fromCache || data.trustScore !== undefined) {
        setResult(data);
        setScanState('complete');
        setProgress(100);
        setStageMessage('');
        return;
      }

      // Job queued — open SSE stream for live updates
      if (data.scanId) {
        setStageMessage('Connecting to scan stream...');
        startSseStream(data.scanId);
      }
    } catch (err) {
      setError(err?.error?.message || 'Failed to submit scan. Please try again.');
      setScanState('error');
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL':   return 'var(--color-critical)';
      case 'HIGH':       return 'var(--color-high)';
      case 'MODERATE':   return 'var(--color-moderate)';
      case 'LOW':        return 'var(--color-low)';
      case 'HIGH_TRUST': return 'var(--color-trust)';
      default:           return 'var(--text-muted)';
    }
  };

  const getRiskIcon = (level) => {
    if (level === 'LOW' || level === 'HIGH_TRUST') {
      return <ShieldCheck size={48} className="result-icon safe" />;
    } else if (level === 'MODERATE') {
      return <Info size={48} className="result-icon" style={{ color: 'var(--color-moderate)', filter: 'drop-shadow(0 0 10px var(--color-moderate-glow))' }} />;
    } else {
      return <AlertTriangle size={48} className="result-icon danger" />;
    }
  };

  const isAnalyzing = scanState === 'queued' || scanState === 'processing';

  // Which stage icon to show
  const stageKey = Object.keys(STAGE_CONFIG).find(k =>
    stageMessage && STAGE_CONFIG[k]?.label === stageMessage
  );
  const StageIcon = (stageKey && STAGE_CONFIG[stageKey]?.icon) || Radio;

  return (
    <div className="analysis-container">
      <header className="analysis-header">
        <h1 className="text-h2 text-gradient">URL Security Analysis</h1>
        <p className="text-body mt-2">Scan links for phishing, malware, and deceptive patterns.</p>
      </header>

      <motion.div
        className="glass-card analysis-input-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <form onSubmit={handleAnalyze} className="analysis-form">
          <div className="input-wrapper">
            <LinkIcon className="input-icon" size={20} />
            <input
              id="url-input"
              type="text"
              className="input-base with-icon"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={isAnalyzing}
            />
          </div>
          <button id="analyze-btn" type="submit" className="btn btn-primary" disabled={isAnalyzing || !url}>
            {isAnalyzing ? (
              <><Loader className="spin" size={18} /> Analyzing...</>
            ) : (
              <><Shield size={18} /> Analyze URL</>
            )}
          </button>
        </form>
        {error && <div className="error-message mt-4 text-small" style={{ color: 'var(--color-critical)' }}>{error}</div>}
      </motion.div>

      {/* ── Live SSE Progress ─────────────────────────────────────────────────── */}
      <AnimatePresence>
        {isAnalyzing && (
          <motion.div
            className="glass-card mt-4"
            style={{ padding: '2rem', textAlign: 'center' }}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            <div style={{ marginBottom: '1rem' }}>
              {scanState === 'queued' ? (
                <>
                  <Clock size={32} style={{ color: 'var(--accent-primary)', marginBottom: '0.75rem' }} />
                  <p className="text-body">Scan queued — warming up engines...</p>
                </>
              ) : (
                <>
                  <StageIcon
                    size={32}
                    style={{ color: 'var(--accent-primary)', marginBottom: '0.75rem' }}
                  />
                  <p className="text-body">{stageMessage}</p>
                </>
              )}
            </div>

            {/* Animated progress bar */}
            <div style={{
              background: 'rgba(255,255,255,0.05)',
              borderRadius: '999px',
              height: '6px',
              overflow: 'hidden',
              width: '100%',
              maxWidth: '400px',
              margin: '0 auto',
            }}>
              <motion.div
                style={{
                  height: '100%',
                  borderRadius: '999px',
                  background: 'linear-gradient(90deg, var(--accent-primary), var(--accent-secondary))',
                }}
                initial={{ width: '5%' }}
                animate={{ width: `${Math.max(progress, 5)}%` }}
                transition={{ duration: 0.6, ease: 'easeOut' }}
              />
            </div>
            <p className="text-small mt-2" style={{ color: 'var(--text-muted)' }}>{progress}% complete</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Results ──────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {result && scanState === 'complete' && (
          <motion.div
            className="results-grid mt-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="glass-card result-main">
              <div className="result-header">
                {getRiskIcon(result.riskLevel)}
                <div className="result-title">
                  <h2 className="text-h2" style={{ color: getRiskColor(result.riskLevel) }}>
                    {result.trustScore}/100
                  </h2>
                  <span className={`risk-badge risk-${result.riskLevel?.toLowerCase() || 'unknown'}`}>
                    {result.riskLevel} RISK
                  </span>
                  {result.fromCache && (
                    <span className="text-small" style={{ color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                      (cached result)
                    </span>
                  )}
                </div>
              </div>

              <div className="result-body">
                <h3 className="text-h4 mb-2">AI Summary</h3>
                <p className="text-body mb-4">{sanitize(result.aiExplanation?.summary) || 'Analysis complete.'}</p>

                {result.aiExplanation?.riskExplanation && (
                  <div className="explanation-box mb-4">
                    <h4 className="text-small font-medium mb-1">Detailed Explanation</h4>
                    <p className="text-small">{sanitize(result.aiExplanation.riskExplanation)}</p>
                  </div>
                )}

                {result.recommendations && result.recommendations.length > 0 && (
                  <>
                    <h3 className="text-h4 mb-2 mt-4">Recommendations</h3>
                    <ul className="recommendations-list">
                      {result.recommendations.map((rec, idx) => (
                        <li key={idx} className="rec-item">
                          <div className="rec-header">
                            <span className={`rec-priority priority-${rec.priority.toLowerCase()}`}>{rec.priority}</span>
                            <span className="rec-title">{rec.title}</span>
                          </div>
                          <p className="text-small mt-1">{rec.action}</p>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            </div>

            <div className="glass-card result-sidebar">
              <h3 className="text-h4 mb-4">Provider Sources</h3>
              <ul className="provider-list">
                {Object.entries(result.sourceStatus || {}).map(([key, status]) => (
                  <li key={key} className="flex-between py-2 border-b">
                    <span className="text-body capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                    <span className={`status-badge status-${status.toLowerCase()}`}>{status}</span>
                  </li>
                ))}
              </ul>

              <div className="mt-6">
                <h4 className="text-small font-medium text-muted mb-2">Analysis Details</h4>
                <div className="text-small flex-between py-1">
                  <span>Confidence</span>
                  <span>{result.confidence}</span>
                </div>
                <div className="text-small flex-between py-1">
                  <span>Evidence Coverage</span>
                  <span>{result.evidenceCoverage}%</span>
                </div>
                <div className="text-small flex-between py-1">
                  <span>Engine Version</span>
                  <span style={{ color: 'var(--text-muted)' }}>{result.ruleSetVersion || 'RISK_ENGINE_V2'}</span>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
