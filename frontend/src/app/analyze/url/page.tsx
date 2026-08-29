'use client';

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Link as LinkIcon, Loader, AlertTriangle, ShieldCheck,
  CheckCircle, Info, Clock, Zap, Radio, Database, Brain,
  BookOpen, TriangleAlert, Lightbulb, Activity, Server
} from 'lucide-react';
import { analyzeService } from '@/services/api';
import { openScanStream } from '@/services/scanStream';
import { sanitize } from '@/utils/sanitize';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

const STAGE_CONFIG: Record<string, { icon: React.ElementType, label: string }> = {
  EVIDENCE_COLLECTION: { icon: Database, label: 'Querying intelligence providers...' },
  RISK_ENGINE:         { icon: Zap,      label: 'Running deterministic risk engine...' },
  AI_EXPLANATION:      { icon: Brain,    label: 'Generating AI explanation...' },
  COMPLETE:            { icon: CheckCircle, label: 'Analysis complete!' },
};

function getCyberEduContent(result: any) {
  const level = result?.riskLevel;
  if (level === 'CRITICAL' || level === 'HIGH') {
    return {
      icon: TriangleAlert,
      color: 'border-rose-200 bg-rose-50/60',
      iconColor: 'text-rose-500',
      title: '⚠️ What This Threat Means For You',
      whatHappened: 'Multiple independent security platforms — including Google Safe Browsing, VirusTotal, and URLScan — flagged this URL. These systems scan billions of URLs daily using machine learning to identify phishing pages, malware distributors, and command-and-control servers.',
      whatCouldHappen: 'If visited: attackers could steal login credentials via a fake page, silently install malware or ransomware, hijack browser sessions, or use your device as part of a botnet.',
      whatToDo: [
        'Do NOT visit this URL or share it with others.',
        'If already visited, immediately change passwords for any recently used accounts.',
        'Run a full malware scan (Windows Defender or Malwarebytes).',
        'Check email for suspicious forwarding rules or login alerts.',
        'Report at safe.google.com/safebrowsing to protect others.',
      ],
      expertNote: 'Phishing URLs mimic legitimate sites using lookalike domains (e.g. "paypa1.com"). Always verify the exact domain in your browser address bar before entering any credentials.',
    };
  }
  if (level === 'MODERATE') {
    return {
      icon: Lightbulb,
      color: 'border-amber-200 bg-amber-50/60',
      iconColor: 'text-amber-500',
      title: '🔍 Caution: Proceed Carefully',
      whatHappened: 'Some security providers raised concerns about this URL. It may be a newly-registered suspicious domain, a site with poor reputation scores, or a legitimate site temporarily compromised.',
      whatCouldHappen: 'Moderate-risk URLs may: redirect you to malicious content, contain drive-by download scripts, or harvest personal data without consent.',
      whatToDo: [
        'Do not enter personal information, passwords, or payment details.',
        'Verify by searching for the organization\'s official website independently.',
        'Inspect the site safely via browserling.com sandbox.',
        'Check domain registration age at whois.domaintools.com.',
      ],
      expertNote: 'Attackers often purchase expired legitimate domains to inherit their SEO reputation. A moderate score doesn\'t mean safe — exercise caution.',
    };
  }
  return {
    icon: ShieldCheck,
    color: 'border-emerald-200 bg-emerald-50/60',
    iconColor: 'text-emerald-500',
    title: '✅ This URL Appears Safe',
    whatHappened: 'No major security providers flagged this URL. It passed checks by Google Safe Browsing, VirusTotal, and URLScan with a clean or trusted record.',
    whatCouldHappen: 'Even safe-scored URLs can occasionally host user-generated malicious content in comment sections or sub-paths. A clean score reflects the root domain, not every page.',
    whatToDo: [
      'Still verify the domain matches your expected destination.',
      'Ensure the site uses HTTPS (padlock icon in browser).',
      'Avoid clicking "Allow Notifications" prompts on unknown sites.',
      'Keep your browser and antivirus software updated.',
    ],
    expertNote: 'No tool provides 100% certainty. Newly created phishing sites can evade detection for 24–72 hours before being flagged. Always stay alert to unusual page behavior.',
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

export default function UrlAnalysis() {
  const [url, setUrl] = useState('');
  const [scanState, setScanState] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [stageMessage, setStageMessage] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
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
          setResult({ trustScore: scan.trustScore, riskLevel: scan.riskLevel, confidence: scan.confidence, evidenceCoverage: scan.evidenceCoverage, riskFactors: scan.riskFactors, aiExplanation: scan.aiExplanation, recommendations: scan.recommendations, completedAt: scan.completedAt });
          setScanState('complete'); setProgress(100); setStageMessage('');
        } else if (scan.status === 'FAILED') {
          resultDeliveredRef.current = true;
          clearInterval(pollIntervalRef.current!);
          setError('Scan failed on the server. Please try again.'); setScanState('error');
        } else {
          setScanState('processing'); setStageMessage('Analyzing...'); setProgress((prev) => Math.min(prev + 8, 90));
        }
      } catch { /* ignore */ }
    }, 3000);
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
    if (!url) return;
    if (closeStreamRef.current) { closeStreamRef.current(); closeStreamRef.current = null; }
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    resultDeliveredRef.current = false;
    scanIdRef.current = null;
    setScanState('queued'); setProgress(5); setStageMessage('Queuing scan...'); setError(null); setResult(null);
    try {
      const response = await analyzeService.url({ url });
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
      setError(err?.error?.message || 'Failed to submit scan. Please try again.'); setScanState('error');
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'text-rose-500';
      case 'HIGH': return 'text-orange-500';
      case 'MODERATE': return 'text-amber-500';
      case 'LOW': return 'text-emerald-500';
      case 'HIGH_TRUST': return 'text-sky-500';
      default: return 'text-slate-500';
    }
  };

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL': case 'HIGH': return <Badge className="bg-rose-500 hover:bg-rose-600 shadow-sm shadow-rose-500/20">{level} RISK</Badge>;
      case 'MODERATE': return <Badge className="bg-amber-400 hover:bg-amber-500 text-slate-900 shadow-sm">{level} RISK</Badge>;
      case 'LOW': case 'HIGH_TRUST': return <Badge className="bg-emerald-400 hover:bg-emerald-500 shadow-sm">{level} RISK</Badge>;
      default: return <Badge variant="outline">UNKNOWN</Badge>;
    }
  };

  const getRiskIcon = (level: string) => {
    if (level === 'LOW' || level === 'HIGH_TRUST') return <ShieldCheck className="w-12 h-12 text-emerald-500" />;
    if (level === 'MODERATE') return <Info className="w-12 h-12 text-amber-500" />;
    return <AlertTriangle className="w-12 h-12 text-rose-500" />;
  };

  const isAnalyzing = scanState === 'queued' || scanState === 'processing';
  const stageKey = Object.keys(STAGE_CONFIG).find(k => stageMessage && STAGE_CONFIG[k]?.label === stageMessage);
  const StageIcon = (stageKey && STAGE_CONFIG[stageKey]?.icon) || Radio;

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header className="text-center mb-12">
        <h1 className="text-4xl font-bold tracking-tight text-slate-900 flex items-center justify-center">
          <LinkIcon className="w-8 h-8 mr-3 text-sky-500" />
          URL Security Analysis
        </h1>
        <p className="text-slate-500 mt-2 text-lg">Scan links for phishing, malware, and deceptive patterns.</p>
      </header>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <GlassCard>
          <form onSubmit={handleAnalyze} className="flex flex-col md:flex-row gap-4 items-center p-2">
            <div className="relative flex-grow w-full">
              <LinkIcon className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={20} />
              <input
                id="url-input"
                type="text"
                className="w-full pl-12 pr-4 py-3 rounded-full border border-slate-200 bg-white/50 focus:outline-none focus:ring-2 focus:ring-sky-400 focus:border-transparent transition-all shadow-sm"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isAnalyzing}
              />
            </div>
            <Button type="submit" disabled={isAnalyzing || !url} className="w-full md:w-auto rounded-full px-8 py-6 text-md font-semibold bg-slate-900 text-white shadow-md hover:shadow-lg transition-all hover:-translate-y-0.5">
              {isAnalyzing ? <><Loader className="w-5 h-5 mr-2 animate-spin" /> Analyzing...</> : <><Shield className="w-5 h-5 mr-2" /> Analyze URL</>}
            </Button>
          </form>
          {error && <div className="mt-4 text-sm text-rose-500 font-medium px-4 pb-4">{error}</div>}
        </GlassCard>
      </motion.div>

      {/* Progress */}
      <AnimatePresence>
        {isAnalyzing && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <GlassCard className="text-center py-8">
              <div className="mb-6 flex flex-col items-center justify-center">
                {scanState === 'queued'
                  ? <><Clock size={32} className="text-sky-500 mb-3 animate-pulse" /><p className="text-slate-700 font-medium">Scan queued — warming up engines...</p></>
                  : <><StageIcon size={32} className="text-sky-500 mb-3 animate-bounce" /><p className="text-slate-700 font-medium">{stageMessage}</p></>}
              </div>
              <div className="w-full max-w-md mx-auto h-2 bg-slate-100 rounded-full overflow-hidden shadow-inner">
                <motion.div className="h-full bg-gradient-to-r from-sky-400 to-cyan-400" initial={{ width: '5%' }} animate={{ width: `${Math.max(progress, 5)}%` }} transition={{ duration: 0.6, ease: 'easeOut' }} />
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

              {/* Score + AI Summary */}
              <GlassCard className="p-8">
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between border-b border-slate-100 pb-6 mb-6">
                  <div className="flex items-center space-x-4 mb-4 md:mb-0">
                    <div className="p-4 rounded-2xl bg-slate-50 border border-slate-100 shadow-sm">{getRiskIcon(result.riskLevel)}</div>
                    <div>
                      <div className="flex items-center space-x-3">
                        <h2 className={`text-5xl font-black tracking-tighter ${getRiskColor(result.riskLevel)}`}>
                          {result.trustScore}<span className="text-2xl text-slate-400 font-medium">/100</span>
                        </h2>
                        {getRiskBadge(result.riskLevel)}
                      </div>
                      {result.fromCache && (
                        <span className="text-xs font-medium text-sky-500 mt-1 block uppercase tracking-wider bg-sky-50 border border-sky-200 px-2 py-0.5 rounded-full w-fit">
                          ⚡ Cached Result
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col items-end space-y-1.5 text-sm text-slate-500">
                    <span className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Confidence: <strong className="text-slate-800">{result.confidence}</strong></span>
                    <span className="flex items-center gap-1.5"><Database className="w-3.5 h-3.5" /> Coverage: <strong className="text-slate-800">{result.evidenceCoverage}%</strong></span>
                    <span className="flex items-center gap-1.5"><Server className="w-3.5 h-3.5" /> Engine: <strong className="text-slate-800">{result.ruleSetVersion || 'RISK_ENGINE_V2'}</strong></span>
                  </div>
                </div>
                <div className="space-y-5">
                  <div>
                    <h3 className="text-base font-bold text-slate-800 flex items-center mb-2"><Brain className="w-5 h-5 mr-2 text-sky-500" /> AI Security Summary</h3>
                    <p className="text-slate-600 leading-relaxed bg-white/60 p-4 rounded-xl border border-white text-sm">
                      {sanitize(result.aiExplanation?.summary) || 'Analysis complete. No specific threats detected in the primary payload.'}
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
                      const provider = PROVIDER_CONFIG[key] || { label: key.replace(/([A-Z])/g, ' $1').trim(), description: 'Security intelligence provider', color: 'bg-slate-100 text-slate-700' };
                      const statusStyle = STATUS_STYLE[status] || STATUS_STYLE.UNAVAILABLE;
                      return (
                        <div key={key} className="flex items-center justify-between p-3 rounded-xl bg-white/50 border border-slate-100 hover:border-slate-200 transition-colors">
                          <div>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${provider.color}`}>{provider.label}</span>
                            <p className="text-[11px] text-slate-400 mt-0.5 ml-0.5">{provider.description}</p>
                          </div>
                          <span className={`text-[10px] font-bold uppercase px-2 py-1 rounded-lg ml-3 ${statusStyle}`}>{status}</span>
                        </div>
                      );
                    })}
                    {(!result.sourceStatus || Object.keys(result.sourceStatus).length === 0) && (
                      <p className="text-sm text-slate-400 italic text-center py-4">Cached result — no live provider breakdown available.</p>
                    )}
                  </div>
                </GlassCard>

                <GlassCard className="p-6">
                  <h3 className="font-bold text-slate-800 flex items-center mb-4 border-b border-slate-100 pb-3">
                    <AlertTriangle className="w-4 h-4 mr-2 text-orange-400" />
                    Risk Factors & Recommendations
                    <span className="ml-auto text-xs text-slate-400 font-normal">Key indicators</span>
                  </h3>
                  {result.riskFactors && result.riskFactors.length > 0 ? (
                    <ul className="space-y-2 mb-4">
                      {result.riskFactors.map((factor: any, idx: number) => (
                        <li key={idx} className="flex items-start gap-2 p-2.5 rounded-lg bg-white/50 border border-slate-100 text-sm">
                          <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${
                            factor.severity === 'CRITICAL' || factor.severity === 'HIGH' ? 'bg-rose-400' :
                            factor.severity === 'MODERATE' ? 'bg-amber-400' : 'bg-emerald-300'
                          }`} />
                          <div className="flex-grow min-w-0">
                            <span className="text-slate-700 font-medium truncate block">{factor.name?.replace(/_/g, ' ')}</span>
                            <span className="text-[10px] text-slate-400">{factor.source}</span>
                          </div>
                          <div className="flex-shrink-0 flex flex-col items-end gap-0.5">
                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                              factor.severity === 'CRITICAL' || factor.severity === 'HIGH' ? 'bg-rose-100 text-rose-700' :
                              factor.severity === 'MODERATE' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'
                            }`}>{factor.severity}</span>
                            <span className="text-[10px] text-slate-400">+{factor.contribution}</span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : <p className="text-sm text-slate-400 italic text-center py-3">No individual risk factors to display.</p>}
                  {result.recommendations && result.recommendations.length > 0 && (
                    <ul className="space-y-2 mt-4">
                      {result.recommendations.slice(0, 3).map((rec: any, idx: number) => (
                        <li key={idx} className="bg-white/50 border border-slate-100 p-2.5 rounded-lg">
                          <div className="flex items-center gap-1.5 mb-1">
                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${rec.priority === 'HIGH' ? 'bg-rose-100 text-rose-700' : rec.priority === 'MEDIUM' ? 'bg-amber-100 text-amber-800' : 'bg-sky-100 text-sky-700'}`}>{rec.priority}</span>
                            <span className="font-semibold text-slate-800 text-xs">{rec.title}</span>
                          </div>
                          <p className="text-[11px] text-slate-600">{rec.action}</p>
                        </li>
                      ))}
                    </ul>
                  )}
                </GlassCard>
              </div>

              {/* Cybersecurity Education Box */}
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
                <div className={`rounded-2xl border-2 p-6 ${edu.color}`}>
                  <div className="flex items-center gap-3 mb-5">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center bg-white/70 shadow-sm`}>
                      <EduIcon className={`w-5 h-5 ${edu.iconColor}`} />
                    </div>
                    <div>
                      <h3 className="font-bold text-slate-900 text-base">{edu.title}</h3>
                      <p className="text-xs text-slate-500 flex items-center gap-1"><BookOpen className="w-3 h-3" /> Cybersecurity Intelligence — by AITrustLens</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-white/60 rounded-xl p-4 border border-white">
                      <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-2">🔎 What Happened</h4>
                      <p className="text-sm text-slate-700 leading-relaxed">{edu.whatHappened}</p>
                    </div>
                    <div className="bg-white/60 rounded-xl p-4 border border-white">
                      <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wide mb-2">⚡ What Could Happen</h4>
                      <p className="text-sm text-slate-700 leading-relaxed">{edu.whatCouldHappen}</p>
                    </div>
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
