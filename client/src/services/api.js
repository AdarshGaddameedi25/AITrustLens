import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_URL,
  withCredentials: true, // Sends httpOnly refresh token cookies automatically
});

// Track whether a token refresh is in progress to prevent multiple concurrent refreshes
let isRefreshing = false;
let failedQueue = [];

function processQueue(error, token = null) {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
}

// ─── Request Interceptor ─────────────────────────────────────────────────────
// Attaches the short-lived access token from memory/localStorage to every request
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ─── Response Interceptor ────────────────────────────────────────────────────
// Handles 401 TOKEN_EXPIRED by silently refreshing the access token via the
// httpOnly refresh token cookie, then replaying the failed request.
api.interceptors.response.use(
  (response) => response.data,
  async (error) => {
    const originalRequest = error.config;

    // Only attempt refresh if:
    // 1. The response is 401 (unauthorized)
    // 2. The error code is TOKEN_EXPIRED
    // 3. We haven't already retried this request
    const errorCode = error.response?.data?.error?.code;
    if (
      error.response?.status === 401 &&
      errorCode === 'TOKEN_EXPIRED' &&
      !originalRequest._retry
    ) {
      if (isRefreshing) {
        // Queue the request until the refresh completes
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // The httpOnly cookie is sent automatically by withCredentials: true
        const response = await api.post('/auth/refresh');
        const newToken = response.data?.token;

        if (newToken) {
          localStorage.setItem('token', newToken);
          api.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
          processQueue(null, newToken);
          originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        processQueue(refreshError, null);
        // Refresh failed — clear session and redirect to login
        localStorage.removeItem('token');
        window.location.href = '/auth';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // For all other errors, format and reject
    if (error.response) {
      return Promise.reject(error.response.data);
    } else if (error.request) {
      return Promise.reject({ error: { message: 'Network error. Please check your connection and ensure the server is running.' } });
    } else {
      return Promise.reject({ error: { message: 'An unexpected error occurred.' } });
    }
  }
);

// ─── Service Methods ─────────────────────────────────────────────────────────

export const analyzeService = {
  url: (urlData) => api.post('/analyze/url', urlData),
  email: (content) => api.post('/analyze/email', { content }),
  scam: (message) => api.post('/analyze/scam', { message }),
  password: (password) => api.post('/analyze/password', { password }),
  privacy: (contentOrUrl) => api.post('/analyze/privacy', contentOrUrl),
  claim: (claimData) => api.post('/analyze/claim', claimData),
  apk: (apkData) => api.post('/analyze/apk', apkData),
  apkUpload: (formData) => api.post('/analyze/apk', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  identity: (email) => api.post('/analyze/identity', { email }),
  qr: (formData) => api.post('/analyze/qr', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
};

export const authService = {
  login: (credentials) => api.post('/auth/login', credentials),
  register: (userData) => api.post('/auth/register', userData),
  logout: () => api.post('/auth/logout'),
  refresh: () => api.post('/auth/refresh'),
  me: () => api.get('/auth/me'),
};

export const dashboardService = {
  getStats: () => api.get('/scans/dashboard'),
  getScans: (params) => api.get('/scans', { params }),
  getScanStatus: (scanId) => api.get(`/scans/${scanId}/status`),
};

export default api;
