import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { User, UserRole } from '../types';

interface AuthState {
  token: string | null;
  user: User | null;
  role: UserRole | null;

  // Actions
  setAuth: (token: string, user: User) => void;
  logout: () => void;
  isAuthenticated: () => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      role: null,

      setAuth: (token, user) =>
        set({ token, user, role: user.role }),

      logout: () =>
        set({ token: null, user: null, role: null }),

      // Helper — use this in components to check login status
      isAuthenticated: () => !!get().token,
    }),
    {
      name: 'qps-auth', // saves to localStorage automatically
    }
  )
);