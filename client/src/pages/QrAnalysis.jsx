import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  QrCode, Upload, Shield, Loader, AlertTriangle, ShieldCheck,
  CheckCircle, Info, Copy, Check, Trash2, Link as LinkIcon, FileText, Smartphone, Mail, CreditCard, Radio, Database, Brain
} from 'lucide-react';
import { analyzeService } from '../services/api';
import { openScanStream } from '../services/scanStream';
import { sanitize } from '../utils/sanitize';
import './Analysis.css';
import './QrAnalysis.css';

const STAGE_CONFIG = {
  EVIDENCE_COLLECTION: { icon: Database, label: 'Querying threat intelligence providers...' },
  RISK_ENGINE:         { icon: Shield,   label: 'Running deterministic risk engine...' },
  AI_EXPLANATION:      { icon: Brain,    label: 'Generating AI explanation...' },
  COMPLETE:            { icon: CheckCircle, label: 'Analysis complete!' },
};

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const MAX_FILE_SIZE_MB = 10;

export default function QrAnalysis() {
  const [file, setFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [scanState, setScanState] = useState('idle'); // idle | decoding | queued | processing | complete | error
  const [progress, setProgress] = useState(0);
  const [stageMessage, setStageMessage] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const fileInputRef = useRef(null);
  const closeStreamRef = useRef(null);

  useEffect(() => {
    return () => {
      if (closeStreamRef.current) closeStreamRef.current();
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  const validateFile = (selectedFile) => {
    if (!selectedFile) return 'No file selected.';
    if (!ALLOWED_MIME_TYPES.includes(selectedFile.type)) {
      return `Invalid file format (${selectedFile.type}). Only PNG, JPEG, GIF, and WebP images are allowed.`;
    }
    if (selectedFile.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
      return `File exceeds the maximum size of ${MAX_FILE_SIZE_MB}MB.`;
    }
    return null;
  };

  const handleFileSelect = (selectedFile) => {
    setError(null);
    setResult(null);
    const valError = validateFile(selectedFile);
    if (valError) {
      setError(valError);
      return;
    }

    setFile(selectedFile);
    const objectUrl = URL.createObjectURL(selectedFile);
    setPreviewUrl(objectUrl);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleReset = () => {
    if (closeStreamRef.current) {
      closeStreamRef.current();
      closeStreamRef.current = null;
    }
    setFile(null);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(null);
    setResult(null);
    setError(null);
    setScanState('idle');
    setProgress(0);
    setStageMessage('');
  };

  const startSseStream = (scanId) => {
    const token = localStorage.getItem('token');

    closeStreamRef.current = openScanStream(scanId, token, {
      onProgress: ({ stage, progress: p, message }) => {
        setScanState('processing');
        setProgress(p ?? 0);
        setStageMessage(message || STAGE_CONFIG[stage]?.label || 'Processing security analysis...');
      },
      onComplete: ({ result: scanResult }) => {
        closeStreamRef.current = null;
        setResult((prev) => ({
          ...(prev || {}),
          ...scanResult,
        }));
        setScanState('complete');
        setProgress(100);
        setStageMessage('');
      },
      onError: (msg) => {
        closeStreamRef.current = null;
        setError(msg || 'Security analysis stream failed.');
        setScanState('error');
      },
    });
  };

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!file) return;

    if (closeStreamRef.current) {
      closeStreamRef.current();
      closeStreamRef.current = null;
    }

    setScanState('decoding');
    setProgress(10);
    setStageMessage('Decoding QR Code image...');
    setError(null);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await analyzeService.qr(formData);
      const data = response.data ?? response;

      setResult(data);

      // If payload is a URL and queued in BullMQ
      if (data.scanId && data.status === 'QUEUED') {
        setScanState('queued');
        setProgress(20);
        setStageMessage('Connecting to real-time security stream...');
        startSseStream(data.scanId);
      } else {
        // Direct / cached / non-URL response
        setScanState('complete');
        setProgress(100);
        setStageMessage('');
      }
    } catch (err) {
      const msg = err?.error?.message || err?.message || 'Failed to decode QR code. Ensure the image is clear.';
      setError(msg);
      setScanState('error');
    }
  };

  const handleCopyContent = () => {
    if (result?.qrContent) {
      navigator.clipboard.writeText(result.qrContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
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

  const getTypeBadgeClass = (type) => {
    switch (type) {
      case 'URL': return 'type-url';
      case 'EMAIL': return 'type-email';
      case 'PHONE': case 'SMS': return 'type-phone';
      case 'CRYPTO_PAYMENT': case 'UPI_PAYMENT': return 'type-payment';
      default: return 'type-text';
    }
  };

  const isAnalyzing = scanState === 'decoding' || scanState === 'queued' || scanState === 'processing';

  return (
    <div className="analysis-container">
      <header className="analysis-header">
        <h1 className="text-h2 text-gradient">QR Code Security Analysis</h1>
        <p className="text-body mt-2">Upload or drag & drop a QR code image to decode payload and analyze destination URLs safely.</p>
      </header>

      {/* Input / Upload Card */}
      <motion.div
        className="glass-card analysis-input-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        {!file ? (
          <div
            className={`qr-upload-box ${dragActive ? 'drag-active' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png, image/jpeg, image/gif, image/webp"
              onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
              style={{ display: 'none' }}
              id="qr-file-input"
            />
            <div style={{ padding: '1rem', borderRadius: '50%', background: 'rgba(99, 102, 241, 0.1)', color: 'var(--accent-primary)' }}>
              <QrCode size={36} />
            </div>
            <div>
              <h3 className="text-h4 font-medium mb-1">Drag & Drop QR Code Image</h3>
              <p className="text-small" style={{ color: 'var(--text-muted)' }}>Supports PNG, JPEG, WebP up to 10MB</p>
            </div>
            <button type="button" className="btn btn-secondary mt-2" onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }}>
              <Upload size={16} /> Browse Files
            </button>
          </div>
        ) : (
          <div className="qr-preview-container flex-between">
            <div className="flex-center" style={{ gap: '1rem' }}>
              <img src={previewUrl} alt="QR Preview" className="qr-preview-img" />
              <div>
                <h4 className="text-h4 font-medium">{file.name}</h4>
                <p className="text-small mt-1" style={{ color: 'var(--text-muted)' }}>
                  {(file.size / (1024 * 1024)).toFixed(2)} MB • {file.type}
                </p>
              </div>
            </div>

            <div className="flex-center" style={{ gap: '0.75rem' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleReset}
                disabled={isAnalyzing}
              >
                <Trash2 size={16} /> Reset
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleAnalyze}
                disabled={isAnalyzing}
              >
                {isAnalyzing ? (
                  <><Loader className="spin" size={18} /> Processing...</>
                ) : (
                  <><Shield size={18} /> Analyze QR Code</>
                )}
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="error-message mt-4 text-small flex-between" style={{ color: 'var(--color-critical)', background: 'rgba(239, 68, 68, 0.1)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(239,68,68,0.2)' }}>
            <span className="flex-center" style={{ gap: '0.5rem' }}>
              <AlertTriangle size={18} /> {error}
            </span>
          </div>
        )}
      </motion.div>

      {/* Progress Card */}
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
              <Loader size={32} className="spin" style={{ color: 'var(--accent-primary)', marginBottom: '0.75rem' }} />
              <p className="text-body">{stageMessage}</p>
            </div>

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

      {/* Results Display */}
      <AnimatePresence>
        {result && scanState === 'complete' && (
          <motion.div
            className="results-container mt-4"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            {/* QR Payload Card */}
            <div className="qr-decoded-card mb-4">
              <div className="flex-between mb-3">
                <div className="flex-center" style={{ gap: '0.5rem' }}>
                  <QrCode size={20} style={{ color: 'var(--accent-primary)' }} />
                  <h3 className="text-h4 font-medium">Decoded QR Code Content</h3>
                </div>
                <span className={`type-badge ${getTypeBadgeClass(result.qrContentType)}`}>
                  {result.qrContentType || 'TEXT'}
                </span>
              </div>

              <div className="qr-content-box flex-between">
                <span>{result.qrContent}</span>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleCopyContent}
                  title="Copy decoded content"
                  style={{ marginLeft: '1rem', padding: '0.4rem 0.6rem' }}
                >
                  {copied ? <Check size={14} style={{ color: '#22c55e' }} /> : <Copy size={14} />}
                </button>
              </div>
              <p className="text-small mt-2" style={{ color: 'var(--text-muted)' }}>
                🔒 <strong>Security Enforcement:</strong> System does not automatically visit or execute decoded links.
              </p>
            </div>

            {/* URL Security Results */}
            {result.qrContentType === 'URL' && result.trustScore !== undefined && (
              <div className="results-grid">
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
                    </div>
                  </div>

                  <div className="result-body">
                    <h3 className="text-h4 mb-2">AI Security Summary</h3>
                    <p className="text-body mb-4">{sanitize(result.aiExplanation?.summary) || 'QR Code URL security analysis complete.'}</p>

                    {result.aiExplanation?.riskExplanation && (
                      <div className="explanation-box mb-4">
                        <h4 className="text-small font-medium mb-1">Detailed Risk Explanation</h4>
                        <p className="text-small">{sanitize(result.aiExplanation.riskExplanation)}</p>
                      </div>
                    )}

                    {result.recommendations && result.recommendations.length > 0 && (
                      <>
                        <h3 className="text-h4 mb-2 mt-4">Security Recommendations</h3>
                        <ul className="recommendations-list">
                          {result.recommendations.map((rec, idx) => (
                            <li key={idx} className="rec-item">
                              <div className="rec-header">
                                <span className={`rec-priority priority-${rec.priority?.toLowerCase()}`}>{rec.priority}</span>
                                <span className="rec-title">{rec.title}</span>
                              </div>
                              <p className="text-small mt-1">{rec.action || rec.detail}</p>
                            </li>
                          ))}
                        </ul>
                      </>
                    )}
                  </div>
                </div>

                <div className="glass-card result-sidebar">
                  <h3 className="text-h4 mb-4">Intelligence Sources</h3>
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
                      <span>Source</span>
                      <span className="font-medium" style={{ color: 'var(--accent-primary)' }}>QR Code Decode</span>
                    </div>
                    <div className="text-small flex-between py-1">
                      <span>Confidence</span>
                      <span>{result.confidence || 'MEDIUM'}</span>
                    </div>
                    <div className="text-small flex-between py-1">
                      <span>Evidence Coverage</span>
                      <span>{result.evidenceCoverage || 0}%</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Non-URL Results */}
            {result.qrContentType !== 'URL' && (
              <div className="glass-card mt-4" style={{ padding: '2rem' }}>
                <h3 className="text-h4 mb-2 flex-center" style={{ justifyContent: 'flex-start', gap: '0.5rem' }}>
                  <Info size={20} style={{ color: 'var(--accent-primary)' }} /> Non-URL Payload Notice
                </h3>
                <p className="text-body mb-4">
                  {result.note || `This QR code contains ${result.qrContentType} content. No URL security analysis was performed.`}
                </p>

                {result.recommendations && result.recommendations.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-small font-medium mb-2">Safety Guidance</h4>
                    <ul className="recommendations-list">
                      {result.recommendations.map((rec, idx) => (
                        <li key={idx} className="rec-item">
                          <div className="rec-header">
                            <span className={`rec-priority priority-${rec.priority?.toLowerCase()}`}>{rec.priority}</span>
                            <span className="rec-title">{rec.title}</span>
                          </div>
                          <p className="text-small mt-1">{rec.action || rec.detail}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
