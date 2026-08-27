import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Key, Loader, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { analyzeService } from '../services/api';
import './Analysis.css';

export default function PasswordAnalysis() {
  const [password, setPassword] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!password) return;
    
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const response = await analyzeService.password(password);
      setResult(response.data);
    } catch (err) {
      setError(err.error?.message || 'Failed to analyze password. Please try again.');
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

  return (
    <div className="analysis-container">
      <header className="analysis-header">
        <h1 className="text-h2 text-gradient">Password Exposure Check</h1>
        <p className="text-body mt-2">
          Check if your password has been exposed in data breaches. 
          <br/>
          <span className="text-small text-muted mt-1 inline-block">
            <Shield size={12} className="inline mr-1" />
            Secure k-anonymity check. Your password is never sent or stored in plaintext.
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
            <Key className="input-icon" size={20} />
            <input 
              type="password" 
              className="input-base with-icon" 
              placeholder="Enter password to check..."
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isAnalyzing}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={isAnalyzing || !password}>
            {isAnalyzing ? (
              <><Loader className="spin" size={18} /> Checking...</>
            ) : (
              <><Shield size={18} /> Check Password</>
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
              {result.breachStatus === 'EXPOSED' ? (
                <AlertTriangle size={48} className="result-icon danger" />
              ) : (
                <ShieldCheck size={48} className="result-icon safe" />
              )}
              <div className="result-title">
                <h2 className="text-h2" style={{color: getRiskColor(result.riskLevel)}}>
                   {result.breachStatus === 'EXPOSED' ? 'EXPOSED' : 'SAFE'}
                </h2>
                {result.breachStatus === 'EXPOSED' && (
                    <span className="text-body" style={{color: 'var(--color-critical)'}}>
                        Found in {result.breachCount?.toLocaleString()} breaches
                    </span>
                )}
              </div>
            </div>
            
            <div className="result-body">
              {result.recommendations && result.recommendations.length > 0 && (
                 <>
                  <h3 className="text-h4 mb-2 mt-2">Recommendations</h3>
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
            <h3 className="text-h4 mb-4">Password Strength</h3>
            
            <div className="mb-4">
                <div className="flex-between py-1 border-b mb-2">
                  <span className="text-body">Strength</span>
                  <span className={`status-badge`} style={{
                      background: result.strengthScore >= 5 ? 'var(--color-low-glow)' : result.strengthScore >= 3 ? 'var(--color-moderate-glow)' : 'var(--color-critical-glow)',
                      color: result.strengthScore >= 5 ? '#86efac' : result.strengthScore >= 3 ? '#fde047' : '#fca5a5'
                  }}>
                      {result.passwordStrength}
                  </span>
                </div>
                
                {result.strengthFeedback && result.strengthFeedback.length > 0 && (
                    <div className="mt-4">
                        <h4 className="text-small font-medium text-muted mb-2">Suggestions</h4>
                        <ul style={{ listStylePosition: 'inside' }} className="text-small text-muted">
                            {result.strengthFeedback.map((feedback, idx) => (
                                <li key={idx}>{feedback}</li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>
            
             <div className="mt-6 pt-4 border-t" style={{borderTop: '1px solid var(--glass-border)'}}>
                 <p className="text-small text-muted">
                    This check uses the Have I Been Pwned API via k-anonymity. Only the first 5 characters of a SHA-1 hash were transmitted.
                 </p>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
