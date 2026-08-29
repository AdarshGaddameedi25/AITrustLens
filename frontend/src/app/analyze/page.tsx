'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Link2, ShieldCheck, Mail, Fingerprint, Lock, EyeOff, Smartphone, FileCode2, Search, CheckCircle } from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';
import { useRouter } from 'next/navigation';

const modules = [
  { id: 'url', name: 'URL Scanner', icon: Link2, desc: 'Detect phishing & malicious links in real time with SSE progress.', path: '/analyze/url', color: 'text-sky-500', bg: 'bg-sky-50' },
  { id: 'apk', name: 'APK Analyzer', icon: FileCode2, desc: 'Reverse-engineer Android manifests for spyware and permission abuse.', path: '/analyze/apk', color: 'text-emerald-500', bg: 'bg-emerald-50' },
  { id: 'qr', name: 'QR Inspector', icon: Search, desc: 'Upload a QR image to decode payload and scan destination URLs safely.', path: '/analyze/qr', color: 'text-purple-500', bg: 'bg-purple-50' },
  { id: 'email', name: 'Email Analysis', icon: Mail, desc: 'Parse headers & detect phishing, spoofing, and urgency manipulation.', path: '/analyze/email', color: 'text-amber-500', bg: 'bg-amber-50' },
  { id: 'identity', name: 'Identity Check', icon: Fingerprint, desc: 'Analyze email identity with MX, SPF, DMARC, and disposable domain checks.', path: '/analyze/identity', color: 'text-rose-500', bg: 'bg-rose-50' },
  { id: 'password', name: 'Password Strength', icon: Lock, desc: 'Evaluate entropy & check for breach exposure via k-anonymity (HIBP).', path: '/analyze/password', color: 'text-indigo-500', bg: 'bg-indigo-50' },
  { id: 'privacy', name: 'Privacy Audit', icon: EyeOff, desc: 'Scan privacy policies for data sales, indefinite retention, and missing rights.', path: '/analyze/privacy', color: 'text-teal-500', bg: 'bg-teal-50' },
  { id: 'scam', name: 'Scam Detection', icon: Smartphone, desc: 'Analyze SMS or chat messages for social engineering and scam patterns.', path: '/analyze/scam', color: 'text-cyan-500', bg: 'bg-cyan-50' },
  { id: 'claim', name: 'Fact Checker', icon: CheckCircle, desc: 'Verify claims against fact-check publishers using the Google Fact Check API.', path: '/analyze/claim', color: 'text-sky-600', bg: 'bg-sky-50' },
];

export default function AllTools() {
  const router = useRouter();

  return (
    <div className="max-w-6xl mx-auto">
      <div className="text-center mb-12">
        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ duration: 0.6 }}>
          <div className="inline-flex items-center space-x-2 bg-white/50 border border-slate-200 backdrop-blur-md px-4 py-1.5 rounded-full mb-5 shadow-sm">
            <span className="flex w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-semibold text-slate-600 tracking-wide uppercase">All Intelligence Modules</span>
          </div>
          <h1 className="text-5xl font-extrabold tracking-tighter text-slate-900 mb-3">Analysis Tools</h1>
          <p className="text-lg text-slate-500 max-w-xl mx-auto">Every security module available on the platform. Select one to begin a deep-scan sequence.</p>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {modules.map((mod, i) => (
          <motion.div key={mod.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.07, duration: 0.4 }}>
            <GlassCard
              className="cursor-pointer group h-full hover:border-sky-200 hover:shadow-sky-100/50 transition-all duration-300 p-5"
              onClick={() => router.push(mod.path)}
            >
              <div className="flex flex-col h-full">
                <div className={`${mod.bg} rounded-xl w-11 h-11 flex items-center justify-center mb-4 shadow-sm border border-white group-hover:scale-110 transition-transform duration-300`}>
                  <mod.icon className={`w-5 h-5 ${mod.color}`} />
                </div>
                <h3 className={`text-base font-bold text-slate-800 mb-1.5 group-hover:${mod.color} transition-colors`}>{mod.name}</h3>
                <p className="text-slate-500 text-sm flex-grow leading-relaxed">{mod.desc}</p>
                <div className="mt-4 flex items-center text-xs font-semibold text-sky-500 opacity-0 group-hover:opacity-100 transition-all translate-y-2 group-hover:translate-y-0 duration-300">
                  Launch <span className="ml-1">→</span>
                </div>
              </div>
            </GlassCard>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
