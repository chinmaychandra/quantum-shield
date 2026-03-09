// Login page — email/password form, stores JWT in Zustand on success
import React, { useState } from 'react';

const Login = ({ onLoginSuccess }: { onLoginSuccess: () => void }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();
  setIsLoading(true);

  // Simulated Authentication Logic
  // In a real app, you would use axios.post('/api/login', { email, password })
  setTimeout(() => {
    const mockJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    
    // 1. Stores JWT (as requested in the image)
    localStorage.setItem('token', mockJWT);
    
    // 2. Authenticates and Redirects
    setIsLoading(false);
    onLoginSuccess(); // This function should handle the redirect to /dashboard
  }, 1500);
};

return (
  <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 p-8 rounded-xl shadow-2xl">
        
        {/* Logo Section */}
        <div className="flex items-center justify-center gap-2 mb-8">
          <span className="text-2xl">🔐</span>
          <h1 className="text-xl font-mono font-bold text-white tracking-widest uppercase">
            QuantumShield
          </h1>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Email Input */}
          <div>
            <label className="block text-xs font-mono text-slate-500 uppercase mb-2">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded text-slate-200 font-mono outline-none focus:border-blue-500 transition-colors"
              placeholder="______________________"
            />
          </div>

          {/* Password Input */}
          <div>
            <label className="block text-xs font-mono text-slate-500 uppercase mb-2">Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded text-slate-200 font-mono outline-none focus:border-blue-500 transition-colors"
              placeholder="_____________________"
            />
          </div>

          {/* Login Button */}
          <button
            type="submit"
            disabled={isLoading}
            className="w-full border border-blue-500/50 bg-blue-500/10 hover:bg-blue-500 hover:text-white text-blue-400 font-mono py-3 rounded transition-all active:scale-95 disabled:opacity-50"
          >
            {isLoading ? "[ AUTHENTICATING... ]" : "[ LOGIN ]"}
          </button>
        </form>

        {/* Footer Note */}
        <p className="mt-8 text-center text-[10px] text-slate-600 font-mono leading-relaxed">
          SECURE TERMINAL ACCESS ONLY<br />
          ACCOUNTS PRE-CONFIGURED BY SYSTEM ADMIN
        </p>
      </div>
    </div>
  );
};

export default Login;
