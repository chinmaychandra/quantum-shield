// src/components/shared/Layout.tsx
// ─── SHARED LAYOUT — wraps all protected pages ───────────────────────────────
// Provides: sidebar nav, top bar, logout button, active route highlight

import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';

const navItems = [
  { to: '/',          icon: '⬛', label: 'Dashboard'  },
  { to: '/inventory', icon: '🗂️', label: 'Inventory'  },
  { to: '/scanner',   icon: '🔍', label: 'Scanner'    },
  { to: '/reports',   icon: '📄', label: 'Reports'    },
];

export const Layout = () => {
  const { user, role, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="    display: 'flex', minHeight: '100vh', background: '#0f1117', color: '#e2e8f0', fontFamily: 'Segoe UI'">

      {/* ── Sidebar ─────────────────────────────── */}
      <aside className="
        width: 220, flexShrink: 0,
        background: '#0a0d14',
        borderRight: '1px solid #1e293b',
        display: 'flex', flexDirection: 'column',
        padding: '0',
      ">
        {/* Logo */}
        <div className=" padding: '24px 20px 20px', borderBottom: '1px solid #1e293b' ">
          <div className=" fontSize: 13, fontWeight: 800, letterSpacing: '0.12em', color: '#00D4FF', textTransform: 'uppercase' ">
            ◈ QPS
          </div>
          <div className=" fontSize: 10, color: '#475569', letterSpacing: '0.08em', marginTop: 2 ">
            QUANTUM PROOF SCANNER
          </div>
        </div>

        {/* Nav */}
        <nav className=" flex: 1, padding: '16px 10px' ">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              style={({ isActive }) => ({
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px 12px', borderRadius: 6,
                marginBottom: 2,
                textDecoration: 'none',
                fontSize: 13, fontWeight: isActive ? 600 : 400,
                color: isActive ? '#00D4FF' : '#64748b',
                background: isActive ? 'rgba(0,212,255,0.08)' : 'transparent',
                borderLeft: isActive ? '2px solid #00D4FF' : '2px solid transparent',
                transition: 'all 0.15s',
              })}
            >
              <span className="fontSize: 16 ">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* User info + logout */}
        <div className =" padding: '16px', borderTop: '1px solid #1e293b'">
          <div className=" fontSize: 12, color: '#94a3b8', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' ">
            {user?.email}
          </div>
          <div className=" fontSize: 10, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 ">
            Role: {role}
          </div>
          <button
            onClick={handleLogout}
            className="
              width: '100%', padding: '7px', borderRadius: 5,
              background: 'transparent', border: '1px solid #334155',
              color: '#64748b', fontSize: 12, cursor: 'pointer',
              transition: 'all 0.15s',
            "
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#ef4444'; e.currentTarget.style.color = '#ef4444'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#334155'; e.currentTarget.style.color = '#64748b'; }}
          >
            Sign Out
          </button>
        </div>
      </aside>

      {/* ── Main content ────────────────────────── */}
      <main className="flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column'">
        <Outlet />
      </main>
    </div>
  );
};