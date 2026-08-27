import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, FileText, Loader, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { analyzeService } from '../services/api';
import { sanitize } from '../utils/sanitize';
import './Analysis.css';

export default function PrivacyAnalysis() {
  const [content, setContent] = useState('');
  const [url, setUrl] = useState('');
  const [inputType, setInputType] = useState('url'); // 'url' or 'text'
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (inputType === 'url' && !url) return;
    if (inputType === 'text' && !content) return;
    
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const payload = inputType === 'url' ? { url } : { content };
      const response = await analyzeService.privacy(payload);
      setResult(response.data);
    } catch (err) {
      setError(err.error?.message || 'Failed to analyze privacy policy. Please try again.');
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
        <h1 className="text-h2 text-gradient">Privacy Policy Analysis</h1>
        <p className="text-body mt-2">Scan privacy policies for excessive data collection, data sales, and lack of user rights.</p>
      </header>

      <motion.div 
        className="glass-card analysis-input-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
            <button 
                type="button" 
                className={`btn ${inputType === 'url' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setInputType('url')}
                style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}
            >
                Provide URL
            </button>
            <button 
                type="button" 
                className={`btn ${inputType === 'text' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setInputType('text')}
                style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}
            >
                Paste Text
            </button>
        </div>

        <form onSubmit={handleAnalyze} className="analysis-form" style={{ flexDirection: 'column' }}>
          {inputType === 'url' ? (
              <div className="input-wrapper" style={{ width: '100%' }}>
                <FileText className="input-icon" size={20} />
                <input 
                  type="text" 
                  className="input-base with-icon" 
                  placeholder="https://example.com/privacy"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={isAnalyzing}
                />
              </div>
          ) : (
              <div className="input-wrapper" style={{ width: '100%' }}>
                <textarea 
                  className="input-base" 
                  placeholder="Paste full privacy policy text here..."
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  disabled={isAnalyzing}
                  style={{ minHeight: '150px' }}
                />
              </div>
          )}
          
          <button type="submit" className="btn btn-primary" disabled={isAnalyzing || (inputType === 'url' && !url) || (inputType === 'text' && !content)} style={{ alignSelf: 'flex-start' }}>
            {isAnalyzing ? (
              <><Loader className="spin" size={18} /> Analyzing...</>
            ) : (
              <><Shield size={18} /> Analyze Policy</>
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
                  <h3 className="text-h4 mb-2 mt-4">Concerns & Recommendations</h3>
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
            <h3 className="text-h4 mb-4">Policy Highlights</h3>
            
            <div className="mb-4">
                <div className="text-small flex-between py-1 border-b">
                  <span>Data Sale Mentioned</span>
                  <span style={{color: result.evidence?.dataSale?.mentioned ? 'var(--color-critical)' : 'var(--color-low)'}}>
                    {result.evidence?.dataSale?.mentioned ? 'Yes' : 'No'}
                  </span>
                </div>
                 <div className="text-small flex-between py-1 border-b">
                  <span>Indefinite Retention</span>
                   <span style={{color: result.evidence?.retention?.indefinite ? 'var(--color-high)' : 'inherit'}}>
                    {result.evidence?.retention?.indefinite ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="text-small flex-between py-1 border-b">
                  <span>Deletion Rights</span>
                   <span style={{color: result.evidence?.userRights?.deletion ? 'var(--color-low)' : 'var(--color-high)'}}>
                    {result.evidence?.userRights?.deletion ? 'Explicit' : 'Unclear/None'}
                  </span>
                </div>
                
                {result.evidence?.dataCollection?.sensitiveTypes?.length > 0 && (
                    <div className="text-small py-2 border-b">
                        <span className="block mb-1 text-muted">Sensitive Data Collected:</span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
                            {result.evidence.dataCollection.sensitiveTypes.map(type => (
                                <span key={type} className="status-badge" style={{background: 'rgba(255,255,255,0.1)', textTransform: 'capitalize'}}>{type}</span>
                            ))}
                        </div>
                    </div>
                )}
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
