import React from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Home, Link2, QrCode, Mail, Smartphone, Key, FileText, CheckCircle, LogOut } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import './Sidebar.css';

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: Home },
  { path: '/analyze/url', label: 'URL Analysis', icon: Link2 },
  { path: '/analyze/qr', label: 'QR Scanner', icon: QrCode },
  { path: '/analyze/email', label: 'Email Phishing', icon: Mail },
  { path: '/analyze/scam', label: 'Scam Messages', icon: Smartphone },
  { path: '/analyze/password', label: 'Password Check', icon: Key },
  { path: '/analyze/privacy', label: 'Privacy Policy', icon: FileText },
  { path: '/analyze/claim', label: 'Fact Checker', icon: CheckCircle },
  { path: '/analyze/apk', label: 'APK Security', icon: Smartphone },
];

export default function Sidebar() {
  const { user, logout } = useAuth();

  return (
    <aside className="sidebar glass-panel">
      <div className="sidebar-header">
        <div className="logo-container">
          <Shield className="logo-icon animate-pulse-glow" size={32} />
          <h1 className="logo-text text-gradient">AITrustLens</h1>
        </div>
      </div>
      
      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon size={20} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="user-profile glass-card">
          <div className="avatar">
            {user?.name ? user.name.charAt(0).toUpperCase() : user?.email?.charAt(0).toUpperCase() || 'U'}
          </div>
          <div className="user-info">
            <span className="user-name" style={{
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                maxWidth: '120px',
                display: 'inline-block'
            }}>
              {user?.name || user?.email || 'User'}
            </span>
            <span className="user-role text-small">{user?.role || 'User'}</span>
          </div>
          <button 
            className="logout-btn" 
            onClick={logout} 
            title="Sign Out"
            style={{ 
              marginLeft: 'auto', 
              background: 'none', 
              border: 'none', 
              color: 'var(--text-muted)', 
              cursor: 'pointer' 
            }}
          >
            <LogOut size={18} />
          </button>
        </div>
      </div>
    </aside>
  );
}
