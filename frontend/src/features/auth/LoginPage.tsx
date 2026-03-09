// src/features/auth/LoginPage.tsx
// ─── LOGIN PAGE ────────────────────────────────────────────────────────────────
// Handles: form validation, API call, JWT storage, redirect to dashboard
// Integrates: authAPI (endpoints.ts), useAuthStore (authStore.ts), React Router

import { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { authAPI } from '../../api/endpoints';
import { useAuthStore } from '../../store/authStore';

// ── Validation schema ─────────────────────────────────────────────────────────
const loginSchema = z.object({
  email: z.string().email('Enter a valid email address'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

type LoginForm = z.infer<typeof loginSchema>;

// ── Component ─────────────────────────────────────────────────────────────────
export const LoginPage = () => {
  const navigate = useNavigate();
  const { setAuth, isAuthenticated } = useAuthStore();
  const [serverError, setServerError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // If already logged in, skip login page
  if (isAuthenticated()) {
    return <Navigate to="/" replace />;
  }

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: LoginForm) => {
    setIsLoading(true);
    setServerError('');

    try {
      // ── INTEGRATION POINT ──────────────────────────────────────────────────
      // authAPI.login calls: POST /api/auth/login
      // Your FastAPI backend must return: { token, user: { id, email, role } }
      const res = await authAPI.login(data.email, data.password);
      const { token, user } = res.data;

      // Store token + user in Zustand (auto-saved to localStorage)
      setAuth(token, user);

      // Redirect to dashboard
      navigate('/', { replace: true });

    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Invalid email or password';
      setServerError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // ── Styles (inline for portability) ──────────────────────────────────────────
  const inputStyle = (hasError: boolean) => ({
    width: '100%',
    padding: '11px 14px',
    background: '#111827',
    border: `1px solid ${hasError ? '#ef4444' : '#1e293b'}`,
    borderRadius: 6,
    color: '#e2e8f0',
    fontSize: 14,
    outline: 'none',
    boxSizing: 'border-box' as const,
    transition: 'border-color 0.15s',
  });

  return (
    <div className="
      minHeight: '100vh',
      background: '#0f1117',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Segoe UI', system-ui, sans-serif,
      padding: 20,
    ">
      {/* Background glow */}
      <div className="
        position: 'fixed', inset: 0, zIndex: 0,
        background: 'radial-gradient(ellipse at 30% 40%, rgba(0,212,255,0.06) 0%, transparent 60%)',
        pointerEvents: 'none',
        " />

      <div className="position: 'relative', zIndex: 1,
        width: '100%', maxWidth: 400,
        background: '#0a0d14',
        border: '1px solid #1e293b',
        borderRadius: 12,
        padding: '40px 36px',
        boxShadow: '0 25px 50px rgba(0,0,0,0.5)',
      ">
        {/* Logo + heading */}
        <div className="textAlign: 'center', marginBottom: 32 ">
          <div className="
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 52, height: 52, borderRadius: 12,
            background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.3)',
            fontSize: 22, marginBottom: 16,
          ">◈</div>
          <h1 className="fontSize: 22, fontWeight: 700, color: '#f1f5f9', margin: '0 0 6px', letterSpacing: '-0.02em' ">
            QPS Portal
          </h1>
          <p className="fontSize: 13, color: '#475569', margin: 0 ">
            Quantum Proof Scanner — Secure Access
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit(onSubmit)} className="display: 'flex', flexDirection: 'column', gap: 16 ">

          {/* Email */}
          <div>
            <label className=" display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6, letterSpacing: '0.05em' ">
              EMAIL ADDRESS
            </label>
            <input
              {...register('email')}
              type="email"
              placeholder="you@company.com"
              className="inputStyle(!!errors.email)"
              onFocus={e => e.target.style.borderColor = '#00D4FF'}
              onBlur={e => e.target.style.borderColor = errors.email ? '#ef4444' : '#1e293b'}
            />
            {errors.email && (
              <p className="fontSize: 11, color: '#ef4444', marginTop: 5 ">
                ⚠ {errors.email.message}
              </p>
            )}
          </div>

          {/* Password */}
          <div>
            <label className=" display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6, letterSpacing: '0.05em' ">
              PASSWORD
            </label>
            <input
              {...register('password')}
              type="password"
              placeholder="••••••••"
              className='inputStyle(!!errors.password)'
              onFocus={e => e.target.style.borderColor = '#00D4FF'}
              onBlur={e => e.target.style.borderColor = errors.password ? '#ef4444' : '#1e293b'}
            />
            {errors.password && (
              <p className= "fontSize: 11, color: '#ef4444', marginTop: 5 ">
                ⚠ {errors.password.message}
              </p>
            )}
          </div>

          {/* Server error */}
          {serverError && (
            <div className="
              padding: '10px 14px', borderRadius: 6,
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              fontSize: 13, color: '#ef4444',
            ">
              ✗ {serverError}
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={isLoading}
            className="
              marginTop: 4,
              padding: '12px',
              borderRadius: 6,
              background: isLoading ? '#1e293b' : 'rgba(0,212,255,0.15)',
              border: '1px solid rgba(0,212,255,0.4)',
              color: isLoading ? '#475569' : '#00D4FF',
              fontSize: 14, fontWeight: 600,
              cursor: isLoading ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s',
              letterSpacing: '0.05em',
            "
          >
            {isLoading ? 'Authenticating...' : 'Sign In →'}
          </button>
        </form>

        <p className="text-center text-xs text-slate-500 mt-6">
          Protected system — authorised personnel only
        </p>
      </div>
    </div>
  );
};