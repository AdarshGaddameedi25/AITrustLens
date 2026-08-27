import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, CheckCircle, Loader, AlertTriangle, Info } from 'lucide-react';
import { analyzeService } from '../services/api';
import { sanitize } from '../utils/sanitize';
import './Analysis.css';

export default function ClaimVerification() {
  const [claim, setClaim] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!claim) return;
    
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeService.claim({ claim });
      setResult(response.data);
    } catch (err) {
      setError(err.error?.message || 'Failed to verify claim. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'FALSE': return 'var(--color-critical)';
      case 'MISLEADING': return 'var(--color-high)';
      case 'MIXED': return 'var(--color-moderate)';
      case 'VERIFIED': return 'var(--color-low)';
      default: return 'var(--text-muted)';
    }
  };

  const getVerdictIcon = (verdict) => {
    if (verdict === 'VERIFIED') {
      return <CheckCircle size={48} className="result-icon safe" />;
    } else if (verdict === 'UNVERIFIED' || verdict === 'MIXED') {
       return <Info size={48} className="result-icon" style={{color: 'var(--color-moderate)', filter: 'drop-shadow(0 0 10px var(--color-moderate-glow))'}} />;
    } else {
      return <AlertTriangle size={48} className="result-icon danger" />;
    }
  };

  return (
    <div className="analysis-container">
      <header className="analysis-header">
        <h1 className="text-h2 text-gradient">AI Fact Checker</h1>
        <p className="text-body mt-2">Verify claims against verified publishers using the Google Fact Check Tools API.</p>
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
              placeholder="Enter a claim or statement to verify (e.g. 'Eating carrots improves your eyesight in the dark')..."
              value={claim}
              onChange={(e) => setClaim(e.target.value)}
              disabled={isAnalyzing}
              style={{ minHeight: '100px' }}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={isAnalyzing || !claim} style={{ alignSelf: 'flex-start' }}>
            {isAnalyzing ? (
              <><Loader className="spin" size={18} /> Verifying...</>
            ) : (
              <><CheckCircle size={18} /> Verify Claim</>
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
              {getVerdictIcon(result.verdict)}
              <div className="result-title">
                <h2 className="text-h2" style={{color: getVerdictColor(result.verdict)}}>
                    {result.verdict}
                </h2>
                <span className={`risk-badge risk-${result.riskLevel?.toLowerCase() || 'unknown'}`}>
                  Confidence: {result.confidence}
                </span>
              </div>
            </div>
            
            <div className="result-body">
              {result.note && (
                  <div className="explanation-box mb-4" style={{ borderColor: 'var(--color-moderate)' }}>
                      <p className="text-small" style={{ color: 'var(--color-moderate)' }}>{result.note}</p>
                  </div>
              )}

              <h3 className="text-h4 mb-2">AI Summary</h3>
              <p className="text-body mb-4">{sanitize(result.aiExplanation?.summary) || 'Analysis complete.'}</p>
              
              {result.aiExplanation?.riskExplanation && (
                <div className="explanation-box mb-4">
                  <h4 className="text-small font-medium mb-1">Detailed Explanation</h4>
                  <p className="text-small">{sanitize(result.aiExplanation.riskExplanation)}</p>
                </div>
              )}

            </div>
          </div>

          <div className="glass-card result-sidebar">
            <h3 className="text-h4 mb-4">Verified Sources</h3>
            
            {result.factCheckResult?.claims && result.factCheckResult.claims.length > 0 ? (
                <ul className="provider-list">
                  {result.factCheckResult.claims.slice(0, 5).map((claimData, idx) => {
                      const review = claimData.reviews?.[0];
                      if (!review) return null;
                      
                      return (
                          <li key={idx} className="py-2 border-b">
                              <span className="text-small font-medium text-muted block mb-1">{review.publisher}</span>
                              <span className="text-body block" style={{ fontSize: '0.9rem' }}>
                                  Verdict: <strong>{review.textualRating}</strong>
                              </span>
                              {review.url && (
                                  <a href={review.url} target="_blank" rel="noreferrer" className="text-small mt-1 block" style={{ color: 'var(--accent-primary)', textDecoration: 'none' }}>
                                      Read article →
                                  </a>
                              )}
                          </li>
                      )
                  })}
                </ul>
            ) : (
                <p className="text-small text-muted">No specific publisher sources found for this claim.</p>
            )}
          </div>
        </motion.div>
      )}
    </div>
  );
}
