import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Smartphone, Loader, AlertTriangle, ShieldCheck, Info, FileCode, Check, Upload, Trash2, ArrowRight } from 'lucide-react';
import { analyzeService } from '../services/api';
import { sanitize } from '../utils/sanitize';
import './Analysis.css';

const PRESETS = {
  banking: {
    appName: 'Secure Wallet',
    packageName: 'com.secure.banking.wallet',
    versionName: '4.2.1',
    permissions: [
      'android.permission.INTERNET',
      'android.permission.ACCESS_NETWORK_STATE',
      'android.permission.RECEIVE_SMS',
      'android.permission.READ_SMS',
      'android.permission.READ_CONTACTS',
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.SYSTEM_ALERT_WINDOW',
    ],
  },
  flashlight: {
    appName: 'Bright Torch',
    packageName: 'com.utility.brightflashlight',
    versionName: '1.0.3',
    permissions: [
      'android.permission.INTERNET',
      'android.permission.CAMERA',
      'android.permission.READ_SMS',
      'android.permission.SEND_SMS',
      'android.permission.ACCESS_FINE_LOCATION',
    ],
  },
  calculator: {
    appName: 'Simple Calc',
    packageName: 'com.standard.calculator',
    versionName: '2.1.0',
    permissions: [
      'android.permission.VIBRATE',
    ],
  },
};

const POPULAR_PERMISSIONS = [
  'android.permission.INTERNET',
  'android.permission.ACCESS_NETWORK_STATE',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.READ_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.SEND_SMS',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.READ_PHONE_STATE',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
  'android.permission.BIND_DEVICE_ADMIN',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.SYSTEM_ALERT_WINDOW',
];

export default function ApkAnalysis() {
  const [appName, setAppName] = useState('');
  const [packageName, setPackageName] = useState('');
  const [versionName, setVersionName] = useState('1.0.0');
  const [selectedPermissions, setSelectedPermissions] = useState([]);
  const [customPermission, setCustomPermission] = useState('');

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analyzeStep, setAnalyzeStep] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);
  // apkMode: 'file' = real APK upload, 'manual' = permission checkbox mode
  const [apkMode, setApkMode] = useState('manual');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const togglePermission = (perm) => {
    setSelectedPermissions((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]
    );
  };

  const handleAddCustomPermission = (e) => {
    e.preventDefault();
    const formatted = customPermission.trim();
    if (formatted && !selectedPermissions.includes(formatted)) {
      setSelectedPermissions((prev) => [...prev, formatted]);
      setCustomPermission('');
    }
  };

  const loadPreset = (key) => {
    const preset = PRESETS[key];
    if (preset) {
      setAppName(preset.appName);
      setPackageName(preset.packageName);
      setVersionName(preset.versionName);
      setSelectedPermissions(preset.permissions);
      setResult(null);
      setError(null);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.name.endsWith('.apk')) {
      setError('Please upload a valid Android package (.apk) file.');
      return;
    }

    // Store the real file reference — manifest will be extracted server-side
    setUploadedFile(file);
    setError(null);
    setResult(null);
  };

  const loadDemoMode = () => {
    // DEMO MODE: loads a clearly-labelled static fixture preset for reviewers without a real APK
    loadPreset('banking');
    setUploadedFile(null);
    setApkMode('manual');
  };

  const handleAnalyze = async (e) => {
    if (e) e.preventDefault();

    // File upload mode: real APK must be selected
    if (apkMode === 'file') {
      if (!uploadedFile) {
        setError('Please select an .apk file to upload and analyze.');
        return;
      }
    } else {
      // Manual mode: at least one permission must be selected
      if (selectedPermissions.length === 0) {
        setError('Please select at least one permission to analyze.');
        return;
      }
    }

    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    const fileSteps = [
      'Uploading APK archive to server...',
      'Decompressing Android zip structure...',
      'Locating AndroidManifest.xml entry...',
      'Decoding binary AXML string pool...',
      'Extracting permissions & component declarations...',
      'Consulting permission threat database...',
      'Applying deterministic risk scoring engine...',
      'Generating AI security analysis...',
    ];
    const manualSteps = [
      'Validating permission list...',
      'Consulting permission threat database...',
      'Applying deterministic risk scoring engine...',
      'Generating AI security analysis...',
    ];
    const steps = apkMode === 'file' ? fileSteps : manualSteps;

    for (let i = 0; i < steps.length; i++) {
      setAnalyzeStep(steps[i]);
      await new Promise((resolve) => setTimeout(resolve, 700));
    }

    try {
      let response;
      if (apkMode === 'file' && uploadedFile) {
        // Real APK upload via multipart/form-data — server extracts manifest
        const formData = new FormData();
        formData.append('apk', uploadedFile);
        response = await analyzeService.apkUpload(formData);
      } else {
        // Manual permission JSON payload
        response = await analyzeService.apk({
          permissions: selectedPermissions,
          appName: appName || 'Android Application',
          packageName: packageName || 'com.example.app',
          versionName: versionName || '1.0.0',
        });
      }
      setResult(response.data);
    } catch (err) {
      setError(err.error?.message || 'Failed to complete APK analysis. Please try again.');
    } finally {
      setIsAnalyzing(false);
      setAnalyzeStep('');
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL': return 'var(--color-critical)';
      case 'HIGH': return 'var(--color-high)';
      case 'MODERATE': return 'var(--color-moderate)';
      case 'LOW': return 'var(--color-low)';
      default: return 'var(--text-muted)';
    }
  };

  const getRiskIcon = (level) => {
    if (level === 'LOW') {
      return <ShieldCheck size={48} className="result-icon safe" />;
    } else if (level === 'MODERATE') {
      return <Info size={48} className="result-icon" style={{ color: 'var(--color-moderate)', filter: 'drop-shadow(0 0 10px var(--color-moderate-glow))' }} />;
    } else {
      return <AlertTriangle size={48} className="result-icon danger" />;
    }
  };

  return (
    <div className="analysis-container">
      <header className="analysis-header">
        <h1 className="text-h2 text-gradient">APK Permission & Threat Analysis</h1>
        <p className="text-body mt-2">Scan Android application manifests for high-risk permissions, spyware flags, and privacy leaks.</p>
      </header>

      {/* Mode Toggle & DEMO button */}
      <div className="preset-selector mb-4" style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <span className="text-small font-medium text-muted">Analysis Mode:</span>
        <button
          className={`btn text-small py-1 px-3 ${apkMode === 'file' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => { setApkMode('file'); setResult(null); setError(null); }}
        >
          <Upload size={14} className="mr-1" /> Upload .apk File
        </button>
        <button
          className={`btn text-small py-1 px-3 ${apkMode === 'manual' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => { setApkMode('manual'); setUploadedFile(null); setResult(null); setError(null); }}
        >
          <Check size={14} className="mr-1" /> Manual Permissions
        </button>

        <span style={{ flex: 1 }} />

        {/* ⚠️ DEMO MODE — loads a static fixture; NOT the default behaviour */}
        <span className="text-tiny text-muted" style={{ borderLeft: '1px solid rgba(255,255,255,0.12)', paddingLeft: '0.75rem' }}>
          No APK? &nbsp;
          <button
            className="btn btn-ghost text-small py-1 px-2"
            style={{ border: '1px dashed rgba(139,92,246,0.5)', color: 'var(--accent-secondary)', fontSize: '0.75rem' }}
            onClick={loadDemoMode}
            title="Loads a static demo preset — not a real APK scan"
          >
            ⚠️ DEMO MODE — Load Fixture Preset
          </button>
        </span>
      </div>

      {apkMode === 'manual' && (
        <div className="preset-selector mb-2" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
          <span className="text-tiny text-muted">Quick presets:</span>
          <button className="btn btn-secondary text-small py-1 px-3" onClick={() => loadPreset('banking')}>Targeted Trojan</button>
          <button className="btn btn-secondary text-small py-1 px-3" onClick={() => loadPreset('flashlight')}>Snooping Utility</button>
          <button className="btn btn-secondary text-small py-1 px-3" onClick={() => loadPreset('calculator')}>Safe App</button>
        </div>
      )}

      <div className="grid grid-2gap mt-2">
        {/* Input Panel */}
        <motion.div
          className="glass-card"
          style={{ padding: '1.5rem' }}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h3 className="text-h4 mb-4">{apkMode === 'file' ? 'APK File Upload' : 'Application Details'}</h3>

          {/* APK File Upload Area — real mode */}
          {apkMode === 'file' && (
          <div className="file-upload-zone mb-4" style={{
            border: `2px dashed ${uploadedFile ? 'var(--accent-primary)' : 'rgba(255, 255, 255, 0.1)'}`,
            borderRadius: '12px',
            padding: '1.5rem',
            textAlign: 'center',
            background: uploadedFile ? 'rgba(139,92,246,0.06)' : 'rgba(255, 255, 255, 0.02)',
            cursor: 'pointer',
            position: 'relative'
          }}>
            <input
              type="file"
              accept=".apk"
              onChange={handleFileUpload}
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                height: '100%',
                opacity: 0,
                cursor: 'pointer'
              }}
            />
            {uploadedFile ? (
              <div className="flex-center" style={{ flexDirection: 'column', gap: '0.5rem' }}>
                <FileCode size={36} style={{ color: 'var(--accent-primary)' }} />
                <span className="text-body font-medium">{uploadedFile.name}</span>
                <span className="text-small text-muted">({(uploadedFile.size / (1024 * 1024)).toFixed(2)} MB) — manifest will be extracted server-side</span>
                <button
                  type="button"
                  className="btn btn-secondary text-small py-1 px-2 mt-2"
                  onClick={(e) => {
                    e.stopPropagation();
                    setUploadedFile(null);
                  }}
                >
                  <Trash2 size={14} className="mr-1" /> Remove
                </button>
              </div>
            ) : (
              <div className="flex-center" style={{ flexDirection: 'column', gap: '0.5rem' }}>
                <Upload size={36} style={{ color: 'var(--text-muted)' }} />
                <span className="text-body font-medium">Drag & Drop .apk or Click to Browse</span>
                <span className="text-small text-muted">Manifest configurations will be extracted automatically</span>
              </div>
            )}
          </div>
          )}

          <form onSubmit={handleAnalyze}>
            {apkMode === 'manual' && (
            <div className="grid grid-2gap mb-4">
              <div>
                <label className="text-small text-muted mb-1 block">Application Name</label>
                <input
                  type="text"
                  className="input-base"
                  placeholder="e.g. My Secure App"
                  value={appName}
                  onChange={(e) => setAppName(e.target.value)}
                  disabled={isAnalyzing}
                />
              </div>
              <div>
                <label className="text-small text-muted mb-1 block">Package Identifier</label>
                <input
                  type="text"
                  className="input-base"
                  placeholder="e.g. com.example.app"
                  value={packageName}
                  onChange={(e) => setPackageName(e.target.value)}
                  disabled={isAnalyzing}
                />
              </div>
            </div>
            )} {/* end manual fields */}

            {apkMode === 'manual' && (
              <>
                <h4 className="text-small font-medium text-muted mb-2">Configure Manifest Permissions ({selectedPermissions.length} selected)</h4>
            
            {/* Quick check permissions list */}
            <div className="permissions-checklist mb-4" style={{
              maxHeight: '180px',
              overflowY: 'auto',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '8px',
              padding: '0.75rem',
              background: 'rgba(0, 0, 0, 0.2)'
            }}>
              {POPULAR_PERMISSIONS.map((perm) => (
                <label key={perm} className="flex-between py-1 px-2 hover-bg-mute cursor-pointer" style={{ borderRadius: '4px' }}>
                  <span className="text-small font-mono">{perm.replace('android.permission.', '')}</span>
                  <input
                    type="checkbox"
                    checked={selectedPermissions.includes(perm)}
                    onChange={() => togglePermission(perm)}
                    disabled={isAnalyzing}
                  />
                </label>
              ))}
            </div>

            {/* Custom permission adder */}
            <div className="flex mb-4">
              <input
                type="text"
                className="input-base mr-2"
                placeholder="Custom permission (e.g. android.permission.BLUETOOTH)"
                value={customPermission}
                onChange={(e) => setCustomPermission(e.target.value)}
                disabled={isAnalyzing}
              />
                <button type="button" className="btn btn-secondary" onClick={handleAddCustomPermission} disabled={isAnalyzing}>Add</button>
              </div>
              </>
            )} {/* end apkMode === manual */}

            <button
              type="submit"
              className="btn btn-primary w-100"
              disabled={isAnalyzing || (apkMode === 'file' ? !uploadedFile : selectedPermissions.length === 0)}
            >
              {isAnalyzing ? (
                <><Loader className="spin" size={18} /> {apkMode === 'file' ? 'Extracting & Analyzing...' : 'Analyzing Package...'}</>
              ) : (
                <><Shield size={18} /> {apkMode === 'file' ? 'Upload & Analyze APK' : 'Run APK Assessment'}</>
              )}
            </button>
          </form>

          {error && <div className="error-message mt-4 text-small" style={{ color: 'var(--color-critical)' }}>{error}</div>}
        </motion.div>

        {/* Results Panel */}
        <div className="glass-card" style={{ padding: '1.5rem', minHeight: '350px', position: 'relative' }}>
          <AnimatePresence mode="wait">
            {isAnalyzing && (
              <motion.div
                className="flex-center"
                style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, flexDirection: 'column', gap: '1rem', background: 'rgba(0,0,0,0.4)', borderRadius: '16px', zIndex: 10 }}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <Loader className="spin" size={48} color="var(--accent-primary)" />
                <span className="text-body font-medium animate-pulse">{analyzeStep}</span>
              </motion.div>
            )}
          </AnimatePresence>

          {result ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex-between"
              style={{ flexDirection: 'column', height: '100%' }}
            >
              <div className="w-100">
                <div className="result-header pb-4 border-b">
                  {getRiskIcon(result.riskLevel)}
                  <div className="result-title">
                    <h2 className="text-h2" style={{ color: getRiskColor(result.riskLevel) }}>{result.trustScore}/100</h2>
                    <span className={`risk-badge risk-${result.riskLevel?.toLowerCase() || 'unknown'}`}>
                      {result.riskLevel} RISK
                    </span>
                  </div>
                </div>

                <div className="mt-4">
                  <h3 className="text-h4 mb-2">Manifest Breakdown</h3>
                  {result.appInfo && (
                    <div className="explanation-box mb-4" style={{ padding: '0.75rem', background: 'rgba(255,255,255,0.03)' }}>
                      <p className="text-small"><strong>Name:</strong> {result.appInfo.appName || 'Unknown'}</p>
                      <p className="text-small"><strong>Package:</strong> {result.appInfo.packageName || 'Unknown'}</p>
                      <p className="text-small"><strong>Version:</strong> {result.appInfo.versionName || '1.0.0'}</p>
                    </div>
                  )}

                  <h4 className="text-small font-medium text-muted mb-2">Permission Summary</h4>
                  <div className="permission-summary-tags mb-4" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {result.permissions?.map((p) => (
                      <span key={p.name} className={`tag tag-risk-${p.level.toLowerCase()}`} style={{
                        padding: '0.25rem 0.5rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        fontFamily: 'monospace',
                        background: p.level === 'CRITICAL' ? 'rgba(239, 68, 68, 0.15)' : p.level === 'HIGH' ? 'rgba(249, 115, 22, 0.15)' : p.level === 'MEDIUM' ? 'rgba(234, 179, 8, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                        border: `1px solid ${getRiskColor(p.level)}`,
                        color: getRiskColor(p.level)
                      }} title={p.description}>
                        {p.name.replace('android.permission.', '')}
                      </span>
                    ))}
                  </div>

                  <h3 className="text-h4 mb-2">AI Summary</h3>
                  <p className="text-body mb-4">{sanitize(result.aiExplanation?.summary) || 'Permissions analysis completed.'}</p>
                  
                  {result.aiExplanation?.riskExplanation && (
                    <div className="explanation-box mb-4">
                      <h4 className="text-small font-medium mb-1">Risk Explanation</h4>
                      <p className="text-small">{sanitize(result.aiExplanation.riskExplanation)}</p>
                    </div>
                  )}

                  {result.recommendations && result.recommendations.length > 0 && (
                    <>
                      <h4 className="text-small font-medium mb-2">Recommendations</h4>
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
            </motion.div>
          ) : (
            <div className="flex-center" style={{ flexDirection: 'column', height: '100%', minHeight: '300px', color: 'var(--text-muted)', gap: '0.75rem' }}>
              <Smartphone size={48} style={{ opacity: 0.3 }} />
              <p className="text-body">Run an assessment to view application permission details, trust scores, and dynamic recommendations.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
