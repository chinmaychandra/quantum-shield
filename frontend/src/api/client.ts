import axios from 'axios';

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// REQUEST interceptor — attach JWT token to every request
apiClient.interceptors.request.use(
  (config) => {
    // Get token from localStorage (Zustand persists it here)
    const authData = localStorage.getItem('qps-auth');
    if (authData) {
      const { state } = JSON.parse(authData);
      if (state?.token) {
        config.headers.Authorization = `Bearer ${state.token}`;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// RESPONSE interceptor — auto logout on 401
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('qps-auth');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
)