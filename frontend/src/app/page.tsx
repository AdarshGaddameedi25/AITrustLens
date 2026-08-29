'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link2, ShieldCheck, Mail, Fingerprint, Lock, EyeOff, Search, FileCode2, Activity, Shield, Zap, Globe, Cpu, LockKeyhole, UserCheck, ServerOff } from 'lucide-react';
import { GlassCard } from '@/components/ui/GlassCard';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { Badge } from '@/components/ui/badge';
import { publicService } from '@/services/api';

const modules = [
  { id: 'url', name: 'URL Scanner', icon: Link2, desc: 'Detect phishing & malicious links', path: '/analyze/url', color: 'text-sky-500', bg: 'bg-sky-500', category: 'Network' },
  { id: 'apk', name: 'APK Analyzer', icon: FileCode2, desc: 'Reverse engineer Android packages', path: '/analyze/apk', color: 'text-fuchsia-500', bg: 'bg-fuchsia-500', category: 'Payload' },
  { id: 'qr', name: 'QR Inspector', icon: Search, desc: 'Safely inspect QR code payloads', path: '/analyze/qr', color: 'text-purple-500', bg: 'bg-purple-500', category: 'Physical' },
  { id: 'email', name: 'Email Analysis', icon: Mail, desc: 'Parse headers & detect spoofing', path: '/analyze/email', color: 'text-amber-500', bg: 'bg-amber-500', category: 'Communication' },
  { id: 'scam', name: 'Scam Detection', icon: ShieldCheck, desc: 'Analyze text for social engineering', path: '/analyze/scam', color: 'text-emerald-500', bg: 'bg-emerald-500', category: 'Content' },
  { id: 'identity', name: 'Identity Check', icon: Fingerprint, desc: 'Analyze exposed credentials & DNS', path: '/analyze/identity', color: 'text-indigo-500', bg: 'bg-indigo-500', category: 'Identity' },
  { id: 'password', name: 'Password Strength', icon: Lock, desc: 'Evaluate entropy and breaches', path: '/analyze/password', color: 'text-rose-500', bg: 'bg-rose-500', category: 'Credential' },
  { id: 'privacy', name: 'Privacy Audit', icon: EyeOff, desc: 'Detect data sales in privacy policies', path: '/analyze/privacy', color: 'text-cyan-500', bg: 'bg-cyan-500', category: 'Compliance' },
  { id: 'claim', name: 'Fact Checker', icon: Globe, desc: 'Verify claims against fact-check APIs', path: '/analyze/claim', color: 'text-teal-500', bg: 'bg-teal-500', category: 'Information' },
];

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.1 } }
};

const itemVariants: any = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
};

export default function DashboardPage() {
  const router = useRouter();
  const { user } = useAuth() as any;
  
  const [scans, setScans] = useState(0);
  const [users, setUsers] = useState(0);
  const [threats, setThreats] = useState(0);

  useEffect(() => {
    let mounted = true;
    
    const fetchStats = async () => {
      try {
        const response = (await publicService.getGlobalStats()) as any;
        if (mounted && response.success && response.data) {
          // Add a tiny animation effect by starting slightly below the real value
          setScans(response.data.totalScans - 15);
          setThreats(response.data.threatsBlocked - 5);
          setUsers(response.data.activeUsers - 2);

          // Fast forward to actual values
          setTimeout(() => {
            if (mounted) {
              setScans(response.data.totalScans);
              setThreats(response.data.threatsBlocked);
              setUsers(response.data.activeUsers);
            }
          }, 800);
        }
      } catch (err) {
        console.error('Failed to fetch global stats', err);
      }
    };

    fetchStats();
    // Poll for updates every 15 seconds
    const interval = setInterval(fetchStats, 15000);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="relative min-h-[90vh] pb-20 overflow-hidden">
      {/* Dynamic Background Orbs */}
      <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
        <motion.div animate={{ scale: [1, 1.1, 1], opacity: [0.3, 0.5, 0.3] }} transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }} className="absolute -top-[20%] -left-[10%] w-[600px] h-[600px] bg-sky-200/40 rounded-full blur-[120px]" />
        <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.2, 0.4, 0.2] }} transition={{ duration: 10, repeat: Infinity, ease: "easeInOut", delay: 2 }} className="absolute top-[40%] -right-[10%] w-[500px] h-[500px] bg-emerald-200/40 rounded-full blur-[100px]" />
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[800px] h-[300px] bg-indigo-100/30 rounded-[100%] blur-[100px]" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-6 pt-12">
        
        {/* Header Section */}
        <div className="text-center mb-16">
          <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
            <div className="inline-flex items-center space-x-2 bg-white/60 backdrop-blur-md px-4 py-2 rounded-full mb-6 shadow-sm border border-slate-200/50">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
              <span className="text-xs font-bold text-slate-700 tracking-wider uppercase">System Online • 100% Secure & Authenticated</span>
            </div>
            <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight text-slate-900 mb-6">
              {user ? `Welcome back, ${user.name || 'Agent'}` : 'Trust What You Click.'}
            </h1>
            <p className="text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed">
              The world&apos;s most advanced omni-channel threat intelligence platform. We analyze URLs, files, and messages in milliseconds to keep you safe from digital deception.
            </p>
          </motion.div>
        </div>

        {/* Real-Time Global Stats Ribbon */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.2 }} className="mb-12">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <GlassCard className="p-6 flex items-center gap-5 border-emerald-100 bg-emerald-50/30">
              <div className="p-4 bg-emerald-100 text-emerald-600 rounded-2xl"><Activity size={28} /></div>
              <div>
                <p className="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-1">Total Scans Performed</p>
                <p className="text-3xl font-black text-slate-800 font-mono">{scans.toLocaleString()}</p>
              </div>
            </GlassCard>
            <GlassCard className="p-6 flex items-center gap-5 border-indigo-100 bg-indigo-50/30">
              <div className="p-4 bg-indigo-100 text-indigo-600 rounded-2xl"><Shield size={28} /></div>
              <div>
                <p className="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-1">Malicious Threats Blocked</p>
                <p className="text-3xl font-black text-slate-800 font-mono">{threats.toLocaleString()}</p>
              </div>
            </GlassCard>
            <GlassCard className="p-6 flex items-center gap-5 border-sky-100 bg-sky-50/30">
              <div className="p-4 bg-sky-100 text-sky-600 rounded-2xl"><UserCheck size={28} /></div>
              <div>
                <p className="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-1">Active Trusted Members</p>
                <p className="text-3xl font-black text-slate-800 font-mono">{users.toLocaleString()}</p>
              </div>
            </GlassCard>
          </div>
        </motion.div>

        {/* The Privacy & Security Guarantee */}
        <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.6, delay: 0.4 }} className="mb-16">
          <div className="relative rounded-3xl overflow-hidden bg-slate-900 text-white p-8 md:p-12 shadow-2xl border border-slate-800">
            <div className="absolute inset-0 bg-gradient-to-r from-emerald-500/10 via-sky-500/10 to-indigo-500/10" />
            <div className="absolute right-0 top-0 w-1/2 h-full opacity-10 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-white to-transparent blur-3xl pointer-events-none" />
            
            <div className="relative z-10">
              <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-400/30 mb-6 py-1.5 px-4 text-sm font-bold tracking-wide">
                Our Security Guarantee
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold mb-4">Your Privacy is our Top Priority.</h2>
              <p className="text-slate-400 text-lg max-w-3xl mb-10 leading-relaxed">
                When you scan a URL, upload a file, or check an email on AITrustLens, you are protected by enterprise-grade security. We believe that security tools should never compromise your privacy. 
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div className="flex flex-col">
                  <div className="w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center mb-4 text-emerald-400">
                    <ServerOff size={24} />
                  </div>
                  <h3 className="text-lg font-bold text-white mb-2">Zero-Log Architecture</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">
                    We do not store, log, or index your private URLs, files, or personal details. Once your scan is complete, the session data is immediately wiped from our volatile memory.
                  </p>
                </div>
                <div className="flex flex-col">
                  <div className="w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center mb-4 text-sky-400">
                    <LockKeyhole size={24} />
                  </div>
                  <h3 className="text-lg font-bold text-white mb-2">End-to-End Encryption</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">
                    All data transmitted between your browser and our risk engine is secured using AES-256 military-grade encryption. Your data cannot be intercepted or read by third parties.
                  </p>
                </div>
                <div className="flex flex-col">
                  <div className="w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center mb-4 text-indigo-400">
                    <ShieldCheck size={24} />
                  </div>
                  <h3 className="text-lg font-bold text-white mb-2">Safe Sandbox Isolation</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">
                    When you check a malicious link, our servers detonate it in a secure, isolated sandbox. You are never exposed to the actual threat, ensuring 100% safety while browsing.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Modules Grid */}
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-slate-800 mb-6 flex items-center">
            <Zap className="w-6 h-6 mr-3 text-amber-500" /> Choose an Analysis Module
          </h2>
          <motion.div variants={containerVariants} initial="hidden" animate="show" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {modules.map((mod) => (
              <motion.div variants={itemVariants} key={mod.id}>
                <GlassCard 
                  className="cursor-pointer group h-full hover:border-slate-300 hover:shadow-2xl hover:shadow-slate-200/50 transition-all duration-300 relative overflow-hidden bg-white/70 backdrop-blur-xl"
                  onClick={() => router.push(mod.path)}
                >
                  <div className={`absolute top-0 left-0 w-full h-1.5 ${mod.bg} transform origin-left scale-x-0 group-hover:scale-x-100 transition-transform duration-500 ease-out`} />
                  
                  <div className="flex flex-col h-full p-7">
                    <div className="flex justify-between items-start mb-6">
                      <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-md border border-slate-100 bg-white group-hover:scale-110 transition-transform duration-300`}>
                        <mod.icon className={`w-7 h-7 ${mod.color}`} />
                      </div>
                      <Badge variant="secondary" className="bg-slate-100 text-slate-500 group-hover:bg-slate-200 transition-colors pointer-events-none font-semibold px-3 py-1">
                        {mod.category}
                      </Badge>
                    </div>
                    
                    <h3 className="text-xl font-bold text-slate-800 mb-3 group-hover:text-slate-900 transition-colors">{mod.name}</h3>
                    <p className="text-slate-500 text-sm flex-grow leading-relaxed">
                      {mod.desc}
                    </p>
                    
                    <div className="mt-8 flex items-center justify-between border-t border-slate-100 pt-4">
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-400 group-hover:text-slate-600 transition-colors flex items-center gap-2">
                        <Lock size={12} /> Secure Scan
                      </span>
                      <div className="w-8 h-8 rounded-full bg-slate-50 border border-slate-200 flex items-center justify-center group-hover:bg-slate-900 group-hover:border-slate-900 group-hover:text-white transition-all duration-300 shadow-sm">
                        <span className="transform group-hover:translate-x-0.5 transition-transform text-lg">→</span>
                      </div>
                    </div>
                  </div>
                </GlassCard>
              </motion.div>
            ))}
          </motion.div>
        </div>

      </div>
    </div>
  );
}
