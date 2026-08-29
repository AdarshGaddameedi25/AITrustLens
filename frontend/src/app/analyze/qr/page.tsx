'use client';

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  QrCode, Shield, Loader, AlertTriangle, ShieldCheck,
  CheckCircle, Info, Copy, Check, Trash2, Database, Brain,
  BookOpen, TriangleAlert, Lightbulb, Activity, Server
} from 'lucide-react';
import { analyzeService } from '@/services/api';
import { openScanStream } from '@/services/scanStream';
import { sanitize } from '@/utils/sanitize';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import Image from 'next/image';

const STAGE_CONFIG: Record<string, { icon: React.ElementType, label: string }> = {
  EVIDENCE_COLLECTION: { icon: Database, label: 'Querying threat intelligence providers...' },
  RISK_ENGINE:         { icon: Shield,   label: 'Running deterministic risk engine...' },
  AI_EXPLANATION:      { icon: Brain,    label: 'Generating AI explanation...' },
  COMPLETE:            { icon: CheckCircle, label: 'Analysis complete!' },
};

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const MAX_FILE_SIZE_MB = 10;

function getCyberEduContent(result: any) {
  const level = result?.riskLevel;
  if (level === 'CRITICAL' || level === 'HIGH') {
    return {
      icon: TriangleAlert,
      color: 'border-rose-200 bg-rose-50/60',
      iconColor: 'text-rose-500',
      title: '⚠️ Dangerous QR Code Detected',
      whatHappened: 'This QR code encodes a URL flagged by multiple intelligence platforms including Google Safe Browsing, VirusTotal, and URLScan. QR phishing ("quishing") is a fast-growing attack vector — victims scan a code without seeing the dangerous URL first.',
      whatCouldHappen: 'If scanned without AITrustLens: malicious redirect to a credential-harvesting page, silent mobile malware installation, browser-based cryptojacking, or unauthorized access to device camera/contacts.',
      whatToDo: [
        'Do NOT visit the URL embedded in this QR code.',
        'If found in your workplace, report to your IT/security team immediately.',
        'Never scan QR codes posted in public places (bus stops, restaurants) without verification.',
        'Use AITrustLens to check every QR code before opening its destination.',
      ],
      expertNote: 'Attackers print malicious QR stickers and paste them over legitimate ones (menus, parking meters, etc.). Always preview the destination URL before proceeding — a legitimate business QR always points to its own verified domain.',
    };
  }
  if (level === 'MODERATE') {
    return {
      icon: Lightbulb,
      color: 'border-amber-200 bg-amber-50/60',
      iconColor: 'text-amber-500',
      title: '🔍 Proceed With Caution',
      whatHappened: 'Some intelligence providers flagged this QR\'s encoded URL. It may lead to a suspicious domain, a URL shortener masking its destination, or a site with a poor reputation.',
      whatCouldHappen: 'Moderate-risk QR destinations may redirect you to unwanted content, tracking pages, or sites requesting excessive device permissions.',
      whatToDo: [
        'Do not enter personal information on the linked site.',
        'Check if the URL uses a shortener (bit.ly, tinyurl) — expand it first with a URL expander tool.',
        'Search for the organization\'s name independently to find their official URL.',
      ],
      expertNote: 'URL shorteners in QR codes are a common deception technique. Any QR from a trusted brand should point directly to their official domain — not through a redirect chain.',
    };
  }
  return {
    icon: ShieldCheck,
    color: 'border-emerald-200 bg-emerald-50/60',
    iconColor: 'text-emerald-500',
    title: '✅ QR Code Appears Safe',
    whatHappened: 'The URL embedded in this QR code passed checks by all major threat intelligence providers. No active phishing, malware, or suspicious domain patterns were detected.',
    whatCouldHappen: 'Even clean QR codes can link to sites with risky sub-pages or user-generated content. The scan covers the root destination URL, not every page on the site.',
    whatToDo: [
      'Still verify the URL matches the organization you expect.',
      'Ensure the linked site uses HTTPS (padlock in browser).',
      'Stay alert if the site requests login credentials or payment info.',
    ],
    expertNote: 'QR safety also depends on physical context — a clean URL on a tampered sticker is still a risk. Always verify the QR code is original, not a sticker placed over another.',
  };
}

const PROVIDER_CONFIG: Record<string, { label: string; description: string; color: string }> = {
  virusTotal: { label: 'VirusTotal', description: '70+ antivirus engines', color: 'bg-indigo-100 text-indigo-700' },
  googleSafeBrowsing: { label: 'Google Safe Browsing', description: 'Social engineering & malware database', color: 'bg-sky-100 text-sky-700' },
  urlScan: { label: 'URLScan.io', description: 'Dynamic behavioral scanner', color: 'bg-purple-100 text-purple-700' },
  rdap: { label: 'RDAP / WHOIS', description: 'Domain registration lookup', color: 'bg-slate-100 text-slate-700' },
  urlhausPhishing: { label: 'URLhaus Phishing DB', description: 'Open-source phishing blacklist', color: 'bg-rose-100 text-rose-700' },
};

const STATUS_STYLE: Record<string, string> = {
  CLEAN: 'bg-emerald-100 text-emerald-700 border border-emerald-200',
  TRUSTED: 'bg-sky-100 text-sky-700 border border-sky-200',
  FLAGGED: 'bg-rose-100 text-rose-700 border border-rose-200',
  SUSPICIOUS: 'bg-amber-100 text-amber-700 border border-amber-200',
  UNAVAILABLE: 'bg-slate-100 text-slate-500 border border-slate-200',
  TIMEOUT: 'bg-slate-100 text-slate-500 border border-slate-200',
};

export default function QrAnalysis() {
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [scanState, setScanState] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [stageMessage, setStageMessage] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const closeStreamRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    return () => {
      if (closeStreamRef.current) closeStreamRef.current();
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  const validateFile = (f: File | null) => {
    if (!f) return 'No file selected.';
    if (!ALLOWED_MIME_TYPES.includes(f.type)) return `Invalid format. Only PNG, JPEG, GIF, WebP allowed.`;
    if (f.size > MAX_FILE_SIZE_MB * 1024 * 1024) return `File exceeds ${MAX_FILE_SIZE_MB}MB.`;
    return null;
  };

  const handleFileSelect = (f: File) => {
    setError(null); setResult(null);
    const err = validateFile(f);
    if (err) { setError(err); return; }
    setFile(f);
    setPreviewUrl(URL.createObjectURL(f));
  };

  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); setDragActive(true); };
  const handleDragLeave = (e: React.DragEvent) => { e.preventDefault(); e.stopPropagation(); setDragActive(false); };
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation(); setDragActive(false);
    if (e.dataTransfer.files?.[0]) handleFileSelect(e.dataTransfer.files[0]);
  };

  const handleReset = () => {
    if (closeStreamRef.current) { closeStreamRef.current(); closeStreamRef.current = null; }
    setFile(null);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(null); setResult(null); setError(null); setScanState('idle'); setProgress(0); setStageMessage('');
  };

  const startSseStream = (scanId: string) => {
    const token = localStorage.getItem('token') || '';
    closeStreamRef.current = (openScanStream as any)(scanId, token, {
      onProgress: ({ stage, progress: p, message }: any) => {
        setScanState('processing'); setProgress(p ?? 0);
        setStageMessage(message || STAGE_CONFIG[stage]?.label || 'Processing...');
      },
      onComplete: ({ result: scanResult }: any) => {
        closeStreamRef.current = null;
        setResult((prev: any) => ({ ...(prev || {}), ...scanResult }));
        setScanState('complete'); setProgress(100); setStageMessage('');
      },
      onError: (msg: string) => {
        closeStreamRef.current = null;
        setError(msg || 'Security analysis failed.'); setScanState('error');
      },
    });
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    if (closeStreamRef.current) { closeStreamRef.current(); closeStreamRef.current = null; }
    setScanState('decoding'); setProgress(10); setStageMessage('Decoding QR Code image...'); setError(null); setResult(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const response = await analyzeService.qr(formData);
      const data = response.data ?? response;
      setResult(data);
      if (data.scanId && data.status === 'QUEUED') {
        setScanState('queued'); setProgress(20); setStageMessage('Connecting to real-time security stream...');
        startSseStream(data.scanId);
      } else {
        setScanState('complete'); setProgress(100); setStageMessage('');
      }
    } catch (err: any) {
      setError(err?.error?.message || 'Failed to decode QR code. Ensure the image is clear.');
      setScanState('error');
    }
  };

  const handleCopyContent = () => {
    if (result?.qrContent) { navigator.clipboard.writeText(result.qrContent); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  };

  const getRiskColor = (level: string) => ({ CRITICAL: 'text-rose-500', HIGH: 'text-orange-500', MODERATE: 'text-amber-500', LOW: 'text-emerald-500', HIGH_TRUST: 'text-sky-500' } as any)[level] || 'text-slate-500';

  const getRiskBadge = (level: string) => {
    if (level === 'CRITICAL' || level === 'HIGH') return <Badge className="bg-rose-500 hover:bg-rose-600 shadow-sm">{level} RISK</Badge>;
    if (level === 'MODERATE') return <Badge className="bg-amber-400 hover:bg-amber-500 text-slate-900 shadow-sm">{level} RISK</Badge>;
    if (level === 'LOW' || level === 'HIGH_TRUST') return <Badge className="bg-emerald-400 hover:bg-emerald-500 shadow-sm">{level} RISK</Badge>;
    return <Badge variant="outline">UNKNOWN</Badge>;
  };

  const getRiskIcon = (level: string) => {
    if (level === 'LOW' || level === 'HIGH_TRUST') return <ShieldCheck className="w-12 h-12 text-emerald-500" />;
    if (level === 'MODERATE') return <Info className="w-12 h-12 text-amber-500" />;
    return <AlertTriangle className="w-12 h-12 text-rose-500" />;
  };

  const isAnalyzing = ['decoding', 'queued', 'processing'].includes(scanState);

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header className="text-center mb-12">
        <h1 className="text-4xl font-bold tracking-tight text-slate-900 flex items-center justify-center">
          <QrCode className="w-8 h-8 mr-3 text-purple-500" />
          QR Code Security Analysis
        </h1>
        <p className="text-slate-500 mt-2 text-lg">Upload or drop a QR code image to decode payload and analyze URLs safely.</p>
      </header>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <GlassCard className="p-8">
          {!file ? (
            <div
              className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all cursor-pointer ${dragActive ? 'border-purple-500 bg-purple-50/50 scale-[1.02]' : 'border-slate-300 hover:border-purple-400 hover:bg-purple-50/30'}`}
              onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input ref={fileInputRef} type="file" accept="image/png,image/jpeg,image/gif,image/webp"
                onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])} className="hidden" id="qr-file-input" />
              <div className="w-20 h-20 mx-auto bg-purple-100 rounded-full flex items-center justify-center mb-4 shadow-inner border border-white">
                <QrCode className="w-10 h-10 text-purple-500" />
              </div>
              <h3 className="text-xl font-bold text-slate-800 mb-2">Drag & Drop QR Code Image</h3>
              <p className="text-slate-500">Supports PNG, JPEG, WebP up to 10MB</p>
            </div>
          ) : (
            <div className="flex flex-col md:flex-row gap-8 items-center bg-white/50 p-6 rounded-2xl border border-white shadow-sm">
              <div className="relative w-48 h-48 rounded-xl overflow-hidden shadow-md border border-slate-200 flex-shrink-0">
                {previewUrl && <Image src={previewUrl} alt="QR Code Preview" fill className="object-cover" />}
              </div>
              <div className="flex flex-col flex-grow w-full space-y-4">
                <div>
                  <h3 className="text-lg font-bold text-slate-800">QR Code Preview</h3>
                  <p className="text-sm text-slate-500">{file.name}</p>
                  <p className="text-xs text-slate-400">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                <div className="flex space-x-3">
                  <Button onClick={handleAnalyze} disabled={isAnalyzing} className="flex-grow bg-slate-900 text-white hover:bg-slate-800 rounded-full py-6 font-semibold shadow-md">
                    {isAnalyzing ? <><Loader className="w-5 h-5 mr-2 animate-spin" /> Analyzing...</> : <><Shield className="w-5 h-5 mr-2" /> Scan QR Code</>}
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

      {/* Progress */}
      <AnimatePresence>
        {isAnalyzing && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <GlassCard className="text-center py-8">
              <div className="mb-6 flex flex-col items-center justify-center">
                <Shield size={32} className="text-purple-500 mb-3 animate-pulse" />
                <p className="text-slate-700 font-medium">{stageMessage}</p>
              </div>
              <div className="w-full max-w-md mx-auto h-2 bg-slate-100 rounded-full overflow-hidden shadow-inner">
                <motion.div className="h-full bg-gradient-to-r from-purple-400 to-fuchsia-400" initial={{ width: '5%' }} animate={{ width: `${Math.max(progress, 5)}%` }} transition={{ duration: 0.6, ease: 'easeOut' }} />
              </div>
              <p className="text-sm text-slate-500 mt-3 font-mono">{progress}% complete</p>
            </GlassCard>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results */}
      <AnimatePresence>
        {result && scanState === 'complete' && (() => {
          const edu = getCyberEduContent(result);
          const EduIcon = edu.icon;
          return (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-5">

              {/* Score + Decoded Content + AI Summary */}
              <GlassCard className="p-8">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between border-b border-slate-100 pb-6 mb-6">
                  <div className="flex items-center space-x-4 mb-4 md:mb-0">
                    <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100 shadow-sm">{getRiskIcon(result.riskLevel)}</div>
                    <div>
                      <div className="flex items-center space-x-3">
                        <h2 className={`text-5xl font-black tracking-tighter ${getRiskColor(result.riskLevel)}`}>
                          {result.trustScore ?? '–'}<span className="text-2xl text-slate-400 font-medium">{result.trustScore !== undefined ? '/100' : ''}</span>
                        </h2>
                        {getRiskBadge(result.riskLevel)}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-col items-end space-y-1.5 text-sm text-slate-500">
                    <span className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Confidence: <strong className="text-slate-800">{result.confidence ?? '–'}</strong></span>
                    <span className="flex items-center gap-1.5"><Database className="w-3.5 h-3.5" /> Coverage: <strong className="text-slate-800">{result.evidenceCoverage ?? '–'}%</strong></span>
                    <span className="flex items-center gap-1.5"><Server className="w-3.5 h-3.5" /> Engine: <strong className="text-slate-800">RISK_ENGINE_V2</strong></span>
                  </div>
                </div>

                <div className="space-y-5">
                  {result.qrContent && (
                    <div className="bg-slate-50/80 p-4 rounded-xl border border-slate-200/60 shadow-sm relative group">
                      <div className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button variant="outline" size="sm" onClick={handleCopyContent} className="h-8 rounded-lg bg-white">
                          {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4 text-slate-500" />}
                        </Button>
                      </div>
                      <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Decoded QR Content</h3>
                      <p className="font-mono text-sm text-slate-800 break-all bg-white p-3 rounded border border-slate-100">{result.qrContent}</p>
                    </div>
                  )}
                  <div>
                    <h3 className="text-base font-bold text-slate-800 flex items-center mb-2"><Brain className="w-5 h-5 mr-2 text-purple-500" /> AI Security Summary</h3>
                    <p className="text-slate-600 leading-relaxed bg-white/60 p-4 rounded-xl border border-white text-sm">
                      {sanitize(result.aiExplanation?.summary) || 'Analysis complete. The QR Code payload was evaluated.'}
                    </p>
                  </div>
                  {result.aiExplanation?.riskExplanation && (
                    <div>
                      <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wider mb-2">Detailed Analysis</h4>
                      <p className="text-sm text-slate-600 bg-rose-50/50 p-4 rounded-xl border border-rose-100/50 leading-relaxed">{sanitize(result.aiExplanation.riskExplanation)}</p>
                    </div>
                  )}
                </div>
              </GlassCard>

              {/* Intelligence Sources + Risk Factors */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <GlassCard className="p-6">
                  <h3 className="font-bold text-slate-800 flex items-center mb-4 border-b border-slate-100 pb-3">
                    <Database className="w-4 h-4 mr-2 text-indigo-500" />
                    Intelligence Sources
                    <span className="ml-auto text-xs text-slate-400 font-normal">How we analyzed this</span>
                  </h3>
                  <div className="space-y-2.5">
                    {Object.entries(result.sourceStatus || {}).map(([key, status]: [string, any]) => {
                      const p = PROVIDER_CONFIG[key] || { label: key.replace(/([A-Z])/g, ' $1').trim(), description: 'Security intelligence provider', color: 'bg-slate-100 text-slate-700' };
                      const s = STATUS_STYLE[status] || STATUS_STYLE.UNAVAILABLE;
                      return (
                        <div key={key} className="flex items-center justify-between p-3 rounded-xl bg-white/50 border border-slate-100 hover:border-slate-200 transition-colors">
                          <div>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${p.color}`}>{p.label}</span>
                            <p className="text-[11px] text-slate-400 mt-0.5 ml-0.5">{p.description}</p>
                          </div>
                          <span className={`text-[10px] font-bold uppercase px-2 py-1 rounded-lg ml-3 ${s}`}>{status}</span>
                        </div>
                      );
                    })}
                    {(!result.sourceStatus || Object.keys(result.sourceStatus).length === 0) && (
                      <p className="text-sm text-slate-400 italic text-center py-4">No live provider breakdown available.</p>
                    )}
                  </div>
                </GlassCard>

                <GlassCard className="p-6">
                  <h3 className="font-bold text-slate-800 flex items-center mb-4 border-b border-slate-100 pb-3">
                    <AlertTriangle className="w-4 h-4 mr-2 text-orange-400" />
                    Risk Factors & Recommendations
                    <span className="ml-auto text-xs text-slate-400 font-normal">Key indicators</span>
                  </h3>
                  {result.riskFactors?.length > 0 ? (
                    <ul className="space-y-2 mb-4">
                      {result.riskFactors.map((f: any, i: number) => (
                        <li key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-white/50 border border-slate-100 text-sm">
                          <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-rose-400' : f.severity === 'MODERATE' ? 'bg-amber-400' : 'bg-emerald-300'}`} />
                          <div className="flex-grow min-w-0">
                            <span className="text-slate-700 font-medium truncate block">{f.name?.replace(/_/g, ' ')}</span>
                            <span className="text-[10px] text-slate-400">{f.source}</span>
                          </div>
                          <div className="flex-shrink-0 flex flex-col items-end gap-0.5">
                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-rose-100 text-rose-700' : f.severity === 'MODERATE' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'}`}>{f.severity}</span>
                            <span className="text-[10px] text-slate-400">+{f.contribution}</span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : <p className="text-sm text-slate-400 italic text-center py-3">No individual risk factors to display.</p>}
                  {result.recommendations?.slice(0, 3).map((rec: any, i: number) => (
                    <li key={i} className="bg-white/50 border border-slate-100 p-2.5 rounded-lg list-none mt-2">
                      <div className="flex items-center gap-1.5 mb-1">
                        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${rec.priority === 'HIGH' ? 'bg-rose-100 text-rose-700' : rec.priority === 'MEDIUM' ? 'bg-amber-100 text-amber-800' : 'bg-sky-100 text-sky-700'}`}>{rec.priority}</span>
                        <span className="font-semibold text-slate-800 text-xs">{rec.title}</span>
                      </div>
                      <p className="text-[11px] text-slate-600">{rec.action}</p>
                    </li>
                  ))}
                </GlassCard>
              </div>

              {/* Cybersecurity Education Box */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
                <div className={`rounded-2xl border-2 p-6 ${edu.color}`}>
                  <div className="flex items-center gap-3 mb-5">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-white/70 shadow-sm">
                      <EduIcon className={`w-5 h-5 ${edu.iconColor}`} />
                    </div>
                    <div>
                      <h3 className="font-bold text-slate-900 text-base">{edu.title}</h3>
                      <p className="text-xs text-slate-500 flex items-center gap-1"><BookOpen className="w-3 h-3" /> Cybersecurity Intelligence — by AITrustLens</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {[
                      { label: '🔎 What Happened', text: edu.whatHappened },
                      { label: '⚡ What Could Happen', text: edu.whatCouldHappen },
                    ].map(({ label, text }) => (
                      <div key={label} className="bg-white/60 rounded-xl p-4 border border-white">
                        <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-2">{label}</h4>
                        <p className="text-sm text-slate-700 leading-relaxed">{text}</p>
                      </div>
                    ))}
                    <div className="bg-white/60 rounded-xl p-4 border border-white">
                      <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-2">✅ What To Do</h4>
                      <ul className="space-y-1.5">
                        {edu.whatToDo.map((step, i) => (
                          <li key={i} className="text-sm text-slate-700 flex items-start gap-1.5">
                            <span className="text-emerald-500 font-bold flex-shrink-0 mt-0.5">→</span> {step}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <div className="mt-4 flex items-start gap-2 bg-white/40 rounded-xl p-3 border border-white/80">
                    <Lightbulb className={`w-4 h-4 flex-shrink-0 mt-0.5 ${edu.iconColor}`} />
                    <p className="text-xs text-slate-600 leading-relaxed"><strong className="text-slate-800">Expert Insight:</strong> {edu.expertNote}</p>
                  </div>
                </div>
              </motion.div>

            </motion.div>
          );
        })()}
      </AnimatePresence>
    </div>
  );
}
