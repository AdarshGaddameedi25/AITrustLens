import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Mail, Loader, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { analyzeService } from '../services/api';
import { sanitize } from '../utils/sanitize';
import './Analysis.css';

export default function EmailAnalysis() {
  const [content, setContent] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!content) return;
    
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeService.email(content);
      setResult(response.data);
    } catch (err) {
      setError(err.error?.message || 'Failed to analyze email. Please try again.');
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

  const getRiskIcon = (level) => {
    if (level === 'LOW' || level === 'HIGH_TRUST') {
      return <ShieldCheck size={48} className="result-icon safe" />;
    } else if (level === 'MODERATE') {
       return <Info size={48} className="result-icon" style={{color: 'var(--color-moderate)', filter: 'drop-shadow(0 0 10px var(--color-moderate-glow))'}} />;
    } else {
      return <AlertTriangle size={48} className="result-icon danger" />;
    }
  };

  return (
    <div className="analysis-container">
      <header className="analysis-header">
        <h1 className="text-h2 text-gradient">Email Phishing Analysis</h1>
        <p className="text-body mt-2">Paste email content and headers to analyze for social engineering, malicious links, and sender spoofing.</p>
      </header>

      <motion.div 
        className="glass-card analysis-input-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <form onSubmit={handleAnalyze} className="analysis-form" style={{ flexDirection: 'column' }}>
          <div className="input-wrapper" style={{ width: '100%' }}>
            <textarea 
              className="input-base" 
              placeholder="Paste full email content here (including headers if possible)..."
              value={content}
              onChange={(e) => setContent(e.target.value)}
              disabled={isAnalyzing}
              style={{ minHeight: '200px' }}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={isAnalyzing || !content} style={{ alignSelf: 'flex-start' }}>
            {isAnalyzing ? (
              <><Loader className="spin" size={18} /> Analyzing...</>
            ) : (
              <><Mail size={18} /> Analyze Email</>
            )}
          </button>
        </form>
        {error && <div className="error-message mt-4 text-small" style={{color: 'var(--color-critical)'}}>{error}</div>}
      </motion.div>

      {result && (
        <motion.div 
          className="results-grid mt-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div className="glass-card result-main">
            <div className="result-header">
              {getRiskIcon(result.riskLevel)}
              <div className="result-title">
                <h2 className="text-h2" style={{color: getRiskColor(result.riskLevel)}}>{result.trustScore}/100</h2>
                <span className={`risk-badge risk-${result.riskLevel?.toLowerCase() || 'unknown'}`}>
                  {result.riskLevel} RISK
                </span>
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
            <h3 className="text-h4 mb-4">Analysis Details</h3>
            
            <div className="mb-4">
                <h4 className="text-small font-medium text-muted mb-2">Indicators Found</h4>
                <div className="text-small flex-between py-1 border-b">
                  <span>Phishing Keywords</span>
                  <span>{result.evidence?.phishingKeywords?.count || 0}</span>
                </div>
                 <div className="text-small flex-between py-1 border-b">
                  <span>Urgency Flags</span>
                  <span>{result.evidence?.urgencyIndicators?.score || 0}</span>
                </div>
                <div className="text-small flex-between py-1 border-b">
                  <span>Links Found</span>
                  <span>{result.evidence?.urlAnalysis?.count || 0}</span>
                </div>
            </div>

            <div className="mt-6">
                <h4 className="text-small font-medium text-muted mb-2">Metadata</h4>
                <div className="text-small flex-between py-1 border-b">
                  <span>Confidence</span>
                  <span>{result.confidence}</span>
                </div>
                 <div className="text-small flex-between py-1 border-b">
                  <span>Evidence Coverage</span>
                  <span>{result.evidenceCoverage}%</span>
                </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
