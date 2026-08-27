import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, User, Loader } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import './Auth.css';

export default function Auth() {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({ email: '', password: '', name: '' });
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const { login, register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isLogin) {
        await login(formData.email, formData.password);
      } else {
        await register(formData.email, formData.password, formData.name);
      }
      navigate('/dashboard');
    } catch (err) {
      setError(err.error?.message || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <div className="auth-container">
      <motion.div 
        className="glass-panel auth-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="auth-header">
          <Shield className="logo-icon animate-pulse-glow mb-4" size={48} />
          <h1 className="text-h2 text-gradient">{isLogin ? 'Welcome Back' : 'Create Account'}</h1>
          <p className="text-body mt-2">
            {isLogin ? 'Sign in to access your security dashboard.' : 'Join AITrustLens to protect your digital identity.'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {!isLogin && (
            <div className="input-group">
              <User className="input-icon" size={20} />
              <input 
                type="text" 
                name="name"
                className="input-base with-icon" 
                placeholder="Full Name (optional)"
                value={formData.name}
                onChange={handleChange}
                disabled={loading}
              />
            </div>
          )}

          <div className="input-group">
            <Mail className="input-icon" size={20} />
            <input 
              type="email" 
              name="email"
              className="input-base with-icon" 
              placeholder="Email Address"
              required
              value={formData.email}
              onChange={handleChange}
              disabled={loading}
            />
          </div>

          <div className="input-group">
            <Lock className="input-icon" size={20} />
            <input 
              type="password" 
              name="password"
              className="input-base with-icon" 
              placeholder="Password"
              required
              value={formData.password}
              onChange={handleChange}
              disabled={loading}
              minLength={8}
            />
          </div>

          {error && <div className="error-message text-small">{error}</div>}

          <button type="submit" className="btn btn-primary auth-submit" disabled={loading}>
            {loading ? <Loader className="spin" size={18} /> : (isLogin ? 'Sign In' : 'Create Account')}
          </button>
        </form>

        <div className="auth-footer">
          <p className="text-small">
            {isLogin ? "Don't have an account? " : "Already have an account? "}
            <button 
              className="auth-switch-btn" 
              onClick={() => { setIsLogin(!isLogin); setError(null); }}
              type="button"
            >
              {isLogin ? 'Sign Up' : 'Sign In'}
            </button>
          </p>
        </div>
      </motion.div>
    </div>
  );
}
