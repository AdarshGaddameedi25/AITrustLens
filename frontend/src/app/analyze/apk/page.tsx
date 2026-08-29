'use client';

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Smartphone, Shield, Loader, AlertTriangle, ShieldCheck, Info, Brain, Trash2, Database, Zap, CheckCircle } from 'lucide-react';
import { analyzeService } from '@/services/api';
import { openScanStream } from '@/services/scanStream';
import { sanitize } from '@/utils/sanitize';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { IntelligenceSourcesPanel, RiskFactorsPanel, CyberEduBox, ScoreHeader } from '@/components/ui/AnalysisResult';

const STAGE_CONFIG: Record<string, { icon: React.ElementType, label: string }> = {
  EVIDENCE_COLLECTION: { icon: Database, label: 'Querying intelligence providers...' },
  RISK_ENGINE:         { icon: Zap,      label: 'Running deterministic risk engine...' },
  AI_EXPLANATION:      { icon: Brain,    label: 'Generating AI explanation...' },
  COMPLETE:            { icon: CheckCircle, label: 'Analysis complete!' },
};

const ALLOWED_MIME_TYPES = ['application/vnd.android.package-archive'];
const MAX_FILE_SIZE_MB = 100;

export default function ApkAnalysis() {
  const [file, setFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [scanState, setScanState] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [stageMessage, setStageMessage] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const closeStreamRef = useRef<(() => void) | null>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const scanIdRef = useRef<string | null>(null);
  const resultDeliveredRef = useRef(false);

  useEffect(() => {
    return () => {
      if (closeStreamRef.current) closeStreamRef.current();
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, []);

  const validateFile = (f: File | null) => {
    if (!f) return 'No file selected.';
    if (!ALLOWED_MIME_TYPES.includes(f.type) && !f.name.endsWith('.apk')) return `Invalid format. Only .apk files are allowed.`;
    if (f.size > MAX_FILE_SIZE_MB * 1024 * 1024) return `File exceeds ${MAX_FILE_SIZE_MB}MB.`;
    return null;
  };

  const handleFileSelect = (f: File) => {
    setError(null); setResult(null);
    const err = validateFile(f);
    if (err) { setError(err); return; }
    setFile(f);
  };

  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); setDragActive(true); };
  const handleDragLeave = (e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); setDragActive(false); };
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation(); setDragActive(false);
    if (e.dataTransfer.files?.[0]) handleFileSelect(e.dataTransfer.files[0]);
  };

  const handleReset = () => {
    if (closeStreamRef.current) { closeStreamRef.current(); closeStreamRef.current = null; }
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    setFile(null); setResult(null); setError(null); setScanState('idle'); setProgress(0); setStageMessage('');
  };

  const startPolling = (scanId: string) => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    pollIntervalRef.current = setInterval(async () => {
      if (resultDeliveredRef.current) { clearInterval(pollIntervalRef.current!); return; }
      try {
        const { dashboardService } = await import('@/services/api');
        const statusRes = await dashboardService.getScanStatus(scanId);
        const scan = statusRes.data ?? statusRes;
        if (scan.status === 'COMPLETED' && scan.trustScore !== undefined) {
          resultDeliveredRef.current = true;
          clearInterval(pollIntervalRef.current!);
          setResult({ ...scan });
          setScanState('complete'); setProgress(100); setStageMessage('');
        } else if (scan.status === 'FAILED') {
          resultDeliveredRef.current = true;
          clearInterval(pollIntervalRef.current!);
          setError('Scan failed on the server. Please try again.'); setScanState('error');
        } else {
          setScanState('processing'); setStageMessage('Analyzing APK...'); setProgress((prev) => Math.min(prev + 5, 90));
        }
      } catch { /* ignore */ }
    }, 5000); // Polling slower for APKs since they take longer
  };

  const startSseStream = (scanId: string) => {
    const token = localStorage.getItem('token') || '';
    closeStreamRef.current = (openScanStream as any)(scanId, token, {
      onProgress: ({ stage, progress: p, message }: any) => {
        resultDeliveredRef.current = false;
        setScanState('processing'); setProgress(p ?? 0);
        setStageMessage(message || STAGE_CONFIG[stage]?.label || 'Processing...');
      },
      onComplete: ({ result: scanResult }: any) => {
        resultDeliveredRef.current = true;
        if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
        closeStreamRef.current = null;
        setResult(scanResult); setScanState('complete'); setProgress(100); setStageMessage('');
      },
      onError: () => {
        closeStreamRef.current = null;
        if (resultDeliveredRef.current) return;
        setStageMessage('Analyzing (polling mode)...');
        if (scanIdRef.current) startPolling(scanIdRef.current);
      },
    });
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    if (closeStreamRef.current) { closeStreamRef.current(); closeStreamRef.current = null; }
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    resultDeliveredRef.current = false;
    scanIdRef.current = null;

    setScanState('queued'); setProgress(5); setStageMessage('Uploading APK for analysis...'); setError(null); setResult(null);
    try {
      const formData = new FormData();
      formData.append('apk', file);
      const response = await analyzeService.apk(formData);
      const data = response.data ?? response;

      if (data.fromCache || data.trustScore !== undefined) {
        setResult(data); setScanState('complete'); setProgress(100); setStageMessage(''); return;
      }
      if (data.scanId) {
        scanIdRef.current = data.scanId;
        setStageMessage('Connecting to scan stream...');
        startSseStream(data.scanId);
        setTimeout(() => { if (!resultDeliveredRef.current && data.scanId) startPolling(data.scanId); }, 5000);
      }
    } catch (err: any) {
      setError(err?.error?.message || err?.message || 'Failed to upload APK. Please try again.');
      setScanState('error');
    }
  };

  const getRiskColor = (l: string) => ({ CRITICAL: 'text-rose-500', HIGH: 'text-orange-500', MODERATE: 'text-amber-500', LOW: 'text-emerald-500', HIGH_TRUST: 'text-sky-500' } as any)[l] || 'text-slate-500';
  const getRiskIcon = (l: string) => l === 'LOW' || l === 'HIGH_TRUST' ? <ShieldCheck className="w-12 h-12 text-emerald-500" /> : l === 'MODERATE' ? <Info className="w-12 h-12 text-amber-500" /> : <AlertTriangle className="w-12 h-12 text-rose-500" />;
  const getRiskBadge = (l: string) => {
    if (l === 'CRITICAL' || l === 'HIGH') return <Badge className="bg-rose-500">{l} RISK</Badge>;
    if (l === 'MODERATE') return <Badge className="bg-amber-400 text-slate-900">{l} RISK</Badge>;
    if (l === 'LOW' || l === 'HIGH_TRUST') return <Badge className="bg-emerald-400">{l} RISK</Badge>;
    return <Badge variant="outline">UNKNOWN</Badge>;
  };

  const isAnalyzing = ['queued', 'processing'].includes(scanState);
  const stageKey = Object.keys(STAGE_CONFIG).find(k => stageMessage && STAGE_CONFIG[k]?.label === stageMessage);
  const StageIcon = (stageKey && STAGE_CONFIG[stageKey]?.icon) || Smartphone;

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header className="text-center mb-12">
        <h1 className="text-4xl font-bold tracking-tight text-slate-900 flex items-center justify-center">
          <Smartphone className="w-8 h-8 mr-3 text-fuchsia-500" /> APK Malware Analysis
        </h1>
        <p className="text-slate-500 mt-2 text-lg">Upload an Android app (.apk) to analyze permissions, detect malware, and evaluate privacy risks.</p>
      </header>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <GlassCard className="p-8">
          {!file ? (
            <div
              className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all cursor-pointer ${dragActive ? 'border-fuchsia-500 bg-fuchsia-50/50 scale-[1.02]' : 'border-slate-300 hover:border-fuchsia-400 hover:bg-fuchsia-50/30'}`}
              onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input ref={fileInputRef} type="file" accept=".apk,application/vnd.android.package-archive"
                onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])} className="hidden" id="apk-file-input" />
              <div className="w-20 h-20 mx-auto bg-fuchsia-100 rounded-full flex items-center justify-center mb-4 shadow-inner border border-white">
                <Smartphone className="w-10 h-10 text-fuchsia-500" />
              </div>
              <h3 className="text-xl font-bold text-slate-800 mb-2">Drag & Drop APK File</h3>
              <p className="text-slate-500">Supports Android .apk files up to 100MB</p>
            </div>
          ) : (
            <div className="flex flex-col md:flex-row gap-8 items-center bg-white/50 p-6 rounded-2xl border border-white shadow-sm">
              <div className="w-24 h-24 bg-fuchsia-100 rounded-2xl flex items-center justify-center flex-shrink-0 shadow-inner border border-white">
                <Smartphone className="w-12 h-12 text-fuchsia-500" />
              </div>
              <div className="flex flex-col flex-grow w-full space-y-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-800 break-all">{file.name}</h3>
                  <p className="text-sm text-slate-500">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                <div className="flex space-x-3">
                  <Button onClick={handleAnalyze} disabled={isAnalyzing} className="flex-grow bg-slate-900 text-white hover:bg-slate-800 rounded-full py-6 font-semibold shadow-md">
                    {isAnalyzing ? <><Loader className="w-5 h-5 mr-2 animate-spin" /> Analyzing...</> : <><Shield className="w-5 h-5 mr-2" /> Analyze APK</>}
                  </Button>
                  <Button variant="outline" onClick={handleReset} disabled={isAnalyzing} className="rounded-full py-6 px-6 text-rose-500 border-rose-200 hover:bg-rose-50">
                    <Trash2 className="w-5 h-5" />
                  </Button>
                </div>
                {error && <div className="text-sm font-medium text-rose-500 bg-rose-50 p-3 rounded-lg border border-rose-100">{error}</div>}
              </div>
            </div>
          )}
        </GlassCard>
      </motion.div>

      <AnimatePresence>
        {isAnalyzing && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <GlassCard className="text-center py-8">
              <div className="mb-6 flex flex-col items-center justify-center">
                <StageIcon size={32} className="text-fuchsia-500 mb-3 animate-pulse" />
                <p className="text-slate-700 font-medium">{stageMessage}</p>
              </div>
              <div className="w-full max-w-md mx-auto h-2 bg-slate-100 rounded-full overflow-hidden shadow-inner">
                <motion.div className="h-full bg-gradient-to-r from-fuchsia-400 to-pink-500" initial={{ width: '5%' }} animate={{ width: `${Math.max(progress, 5)}%` }} transition={{ duration: 0.6, ease: 'easeOut' }} />
              </div>
              <p className="text-sm text-slate-500 mt-3 font-mono">{progress}% complete</p>
            </GlassCard>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {result && scanState === 'complete' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-5">
            <GlassCard className="p-8">
              <ScoreHeader result={result} getRiskIcon={getRiskIcon} getRiskColor={getRiskColor} getRiskBadge={getRiskBadge} />
              <div className="space-y-5">
                <div>
                  <h3 className="text-base font-bold text-slate-800 flex items-center mb-2"><Brain className="w-5 h-5 mr-2 text-fuchsia-500" /> AI Security Summary</h3>
                  <p className="text-slate-600 text-sm leading-relaxed bg-white/60 p-4 rounded-xl border border-white">{sanitize(result.aiExplanation?.summary) || 'Analysis complete. APK permissions evaluated.'}</p>
                </div>
                {result.aiExplanation?.riskExplanation && (
                  <div>
                    <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wider mb-2">Detailed Analysis</h4>
                    <p className="text-sm text-slate-600 bg-fuchsia-50/50 p-4 rounded-xl border border-fuchsia-100/50 leading-relaxed">{sanitize(result.aiExplanation.riskExplanation)}</p>
                  </div>
                )}
              </div>
            </GlassCard>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <IntelligenceSourcesPanel sourceStatus={result.sourceStatus} />
              <RiskFactorsPanel riskFactors={result.riskFactors} recommendations={result.recommendations} />
            </div>
            {/* Fallback to generic CyberEduBox since APK wasn't explicitly modeled in getCyberEduContent, it will automatically fallback cleanly */}
            <CyberEduBox moduleType="apk" result={result} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
