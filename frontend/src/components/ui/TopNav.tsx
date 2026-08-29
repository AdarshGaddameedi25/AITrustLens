'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion } from 'framer-motion';
import { ShieldCheck, LogOut, User } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';

const navLinks = [
  { name: 'Dashboard', path: '/' },
  { name: 'URL Scan', path: '/analyze/url' },
  { name: 'APK Scan', path: '/analyze/apk' },
  { name: 'QR Scan', path: '/analyze/qr' },
  { name: 'All Tools', path: '/analyze' },
];

export const TopNav = () => {
  const pathname = usePathname();
  const { user, logout, loading } = useAuth() as any;

  return (
    <motion.nav
      initial={{ y: -100, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.8, ease: 'easeOut' }}
      className="fixed top-0 left-0 right-0 z-50 flex justify-center pt-6 px-4"
    >
      <div className="flex items-center justify-between w-full max-w-5xl px-8 py-3 glass-effect rounded-full shadow-lg border border-white/50">
        
        {/* Logo */}
        <Link href="/" className="flex items-center space-x-2 group">
          <div className="bg-gradient-to-br from-sky-400 to-cyan-500 p-2 rounded-full shadow-md group-hover:shadow-cyan-400/50 transition-shadow">
            <ShieldCheck className="w-5 h-5 text-white" />
          </div>
          <span className="font-bold text-xl tracking-tight text-slate-800">
            AITrust<span className="font-light text-slate-500">Lens</span>
          </span>
        </Link>

        {/* Links */}
        <div className="hidden md:flex space-x-1">
          {navLinks.map((link) => {
            const isActive = pathname === link.path;
            return (
              <Link
                key={link.name}
                href={link.path}
                className={`relative px-4 py-2 text-sm font-medium transition-colors rounded-full ${
                  isActive ? 'text-slate-900' : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="nav-indicator"
                    className="absolute inset-0 bg-white/60 rounded-full shadow-sm border border-white/80"
                    initial={false}
                    transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                  />
                )}
                <span className="relative z-10">{link.name}</span>
              </Link>
            );
          })}
        </div>

        {/* Action Button */}
        {!loading && user ? (
          <div className="flex items-center space-x-3">
             <div className="hidden md:flex items-center text-sm font-medium text-slate-600 bg-white/50 px-3 py-1.5 rounded-full border border-slate-200">
               <User className="w-4 h-4 mr-2 text-slate-400" />
               {user.name || user.email}
             </div>
             <Button 
               onClick={logout} 
               variant="outline" 
               className="rounded-full px-4 py-2 border-slate-300 text-slate-600 hover:bg-rose-50 hover:text-rose-600 hover:border-rose-200 transition-colors"
               size="sm"
             >
               <LogOut className="w-4 h-4" />
             </Button>
          </div>
        ) : (
          <Link href="/auth">
            <Button className="px-5 py-2 text-sm font-semibold text-white bg-slate-900 rounded-full hover:bg-slate-800 transition-colors shadow-md hover:shadow-lg">
              Sign In
            </Button>
          </Link>
        )}
      </div>
    </motion.nav>
  );
};
