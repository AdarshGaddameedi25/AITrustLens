import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Smartphone, Loader, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { analyzeService } from '../services/api';
import { sanitize } from '../utils/sanitize';
import './Analysis.css';

export default function ScamAnalysis() {
  const [message, setMessage] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!message) return;
    
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeService.scam(message);
      setResult(response.data);
    } catch (err) {
      setError(err.error?.message || 'Failed to analyze message. Please try again.');
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
        <h1 className="text-h2 text-gradient">Scam Message Detection</h1>
        <p className="text-body mt-2">Paste SMS or chat messages to identify common scam patterns and social engineering tactics.</p>
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
              placeholder="Paste message content here..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={isAnalyzing}
              style={{ minHeight: '150px' }}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={isAnalyzing || !message} style={{ alignSelf: 'flex-start' }}>
            {isAnalyzing ? (
              <><Loader className="spin" size={18} /> Analyzing...</>
            ) : (
              <><Smartphone size={18} /> Analyze Message</>
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
                <h4 className="text-small font-medium text-muted mb-2">Detected Patterns</h4>
                <div className="text-small flex-between py-1 border-b">
                  <span>Financial Request</span>
                  <span style={{color: result.evidence?.financialRequest?.detected ? 'var(--color-critical)' : 'inherit'}}>
                    {result.evidence?.financialRequest?.detected ? 'Yes' : 'No'}
                  </span>
                </div>
                 <div className="text-small flex-between py-1 border-b">
                  <span>Credential Request</span>
                   <span style={{color: result.evidence?.credentialRequest?.detected ? 'var(--color-critical)' : 'inherit'}}>
                    {result.evidence?.credentialRequest?.detected ? 'Yes' : 'No'}
                  </span>
                </div>
                {result.evidence?.detectedCategories?.length > 0 && (
                    <div className="text-small py-2 border-b">
                        <span className="block mb-1 text-muted">Scam Categories:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                            {result.evidence.detectedCategories.map(cat => (
                                <span key={cat} className="status-badge" style={{background: 'rgba(255,255,255,0.1)'}}>{cat}</span>
                            ))}
                        </div>
                    </div>
                )}
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
