'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Smartphone, Loader, AlertTriangle, ShieldCheck, Info, Brain } from 'lucide-react';
import { analyzeService } from '@/services/api';
import { sanitize } from '@/utils/sanitize';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { IntelligenceSourcesPanel, RiskFactorsPanel, CyberEduBox, ScoreHeader } from '@/components/ui/AnalysisResult';

export default function ScamAnalysis() {
  const [message, setMessage] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!message) return;
    setIsAnalyzing(true); setError(null); setResult(null);
    try {
      const response = await analyzeService.scam(message);
      setResult(response.data ?? response);
    } catch (err: any) {
      setError(err.error?.message || 'Failed to analyze message. Please try again.');
    } finally { setIsAnalyzing(false); }
  };

  const getRiskColor = (l: string) => ({ CRITICAL: 'text-rose-500', HIGH: 'text-orange-500', MODERATE: 'text-amber-500', LOW: 'text-emerald-500', HIGH_TRUST: 'text-sky-500' } as any)[l] || 'text-slate-500';
  const getRiskIcon = (l: string) => l === 'LOW' || l === 'HIGH_TRUST' ? <ShieldCheck className="w-12 h-12 text-emerald-500" /> : l === 'MODERATE' ? <Info className="w-12 h-12 text-amber-500" /> : <AlertTriangle className="w-12 h-12 text-rose-500" />;
  const getRiskBadge = (l: string) => {
    if (l === 'CRITICAL' || l === 'HIGH') return <Badge className="bg-rose-500">{l} RISK</Badge>;
    if (l === 'MODERATE') return <Badge className="bg-amber-400 text-slate-900">{l} RISK</Badge>;
    if (l === 'LOW' || l === 'HIGH_TRUST') return <Badge className="bg-emerald-400">{l} RISK</Badge>;
    return <Badge variant="outline">UNKNOWN</Badge>;
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header className="text-center mb-10">
        <h1 className="text-4xl font-bold tracking-tight text-slate-900 flex items-center justify-center">
          <Smartphone className="w-8 h-8 mr-3 text-emerald-500" /> SMS & Messaging Scam Analysis
        </h1>
        <p className="text-slate-500 mt-2 text-lg">Paste suspicious text messages, WhatsApp forwards, or direct messages to analyze for scams.</p>
      </header>
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <GlassCard className="p-6">
          <form onSubmit={handleAnalyze} className="space-y-4">
            <textarea className="w-full px-4 py-3 rounded-xl border border-slate-200 bg-white/50 focus:ring-2 focus:ring-emerald-400 focus:outline-none transition-all min-h-[150px] text-sm font-sans"
              placeholder="Paste the suspicious message here..."
              value={message} onChange={(e) => setMessage(e.target.value)} disabled={isAnalyzing} />
            <Button type="submit" disabled={isAnalyzing || !message} className="bg-slate-900 text-white rounded-full px-8 py-6 font-semibold hover:bg-slate-800 shadow-md transition-all hover:-translate-y-0.5">
              {isAnalyzing ? <><Loader className="w-5 h-5 mr-2 animate-spin" /> Analyzing...</> : <><Smartphone className="w-5 h-5 mr-2" /> Analyze Message</>}
            </Button>
          </form>
          {error && <div className="mt-4 text-sm font-medium text-rose-500 bg-rose-50 p-3 rounded-lg border border-rose-100">{error}</div>}
        </GlassCard>
      </motion.div>
      <AnimatePresence>
        {result && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-5">
            <GlassCard className="p-8">
              <ScoreHeader result={result} getRiskIcon={getRiskIcon} getRiskColor={getRiskColor} getRiskBadge={getRiskBadge} />
              <div className="space-y-5">
                <div>
                  <h3 className="text-base font-bold text-slate-800 flex items-center mb-2"><Brain className="w-5 h-5 mr-2 text-emerald-500" /> AI Security Summary</h3>
                  <p className="text-slate-600 text-sm leading-relaxed bg-white/60 p-4 rounded-xl border border-white">{sanitize(result.aiExplanation?.summary) || 'Analysis complete.'}</p>
                </div>
                {result.aiExplanation?.riskExplanation && (
                  <div>
                    <h4 className="text-xs font-bold text-slate-600 uppercase tracking-wider mb-2">Detailed Analysis</h4>
                    <p className="text-sm text-slate-600 bg-emerald-50/50 p-4 rounded-xl border border-emerald-100/50 leading-relaxed">{sanitize(result.aiExplanation.riskExplanation)}</p>
                  </div>
                )}
              </div>
            </GlassCard>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <IntelligenceSourcesPanel sourceStatus={result.sourceStatus} />
              <RiskFactorsPanel riskFactors={result.riskFactors} recommendations={result.recommendations} />
            </div>
            <CyberEduBox moduleType="scam" result={result} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
