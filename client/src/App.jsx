import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import UrlAnalysis from './pages/UrlAnalysis';
import QrAnalysis from './pages/QrAnalysis';
import EmailAnalysis from './pages/EmailAnalysis';
import PasswordAnalysis from './pages/PasswordAnalysis';
import ScamAnalysis from './pages/ScamAnalysis';
import PrivacyAnalysis from './pages/PrivacyAnalysis';
import ClaimVerification from './pages/ClaimVerification';
import ApkAnalysis from './pages/ApkAnalysis';
import IdentityAnalysis from './pages/IdentityAnalysis';
import Auth from './pages/Auth';
import { Loader } from 'lucide-react';

const ProtectedLayout = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex-center" style={{ height: '100vh', width: '100vw' }}>
        <Loader className="spin" size={48} color="var(--accent-primary)" />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/auth" replace />;
  }

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
};

const PublicLayout = () => {
  const { user, loading } = useAuth();

  if (loading) return null; // or spinner
  
  // If user is already logged in, redirect to dashboard
  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="app-layout">
      <main style={{ width: '100vw' }}>
        <Outlet />
      </main>
    </div>
  );
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="app-background"></div>
        <Routes>
          {/* Public routes */}
          <Route element={<PublicLayout />}>
            <Route path="/auth" element={<Auth />} />
          </Route>

          {/* Protected routes */}
          <Route element={<ProtectedLayout />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/analyze/url" element={<UrlAnalysis />} />
            <Route path="/analyze/qr" element={<QrAnalysis />} />
            <Route path="/analyze/email" element={<EmailAnalysis />} />
            <Route path="/analyze/scam" element={<ScamAnalysis />} />
            <Route path="/analyze/password" element={<PasswordAnalysis />} />
            <Route path="/analyze/privacy" element={<PrivacyAnalysis />} />
            <Route path="/analyze/claim" element={<ClaimVerification />} />
            <Route path="/analyze/apk" element={<ApkAnalysis />} />
            <Route path="/analyze/identity" element={<IdentityAnalysis />} />
            
            {/* Catch all for unimplemented routes */}
            <Route path="/analyze/*" element={
              <div className="flex-center" style={{ height: '50vh', flexDirection: 'column', gap: '1rem' }}>
                <h2 className="text-h2">Coming Soon</h2>
                <p className="text-body text-muted">This analyzer is currently under construction.</p>
              </div>
            } />
          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
