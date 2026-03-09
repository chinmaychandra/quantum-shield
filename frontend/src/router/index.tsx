import { createBrowserRouter, Navigate } from "react-router-dom";

// ── Shared components ──────────────────────────────────
import { ProtectedRoute } from "../components/shared/ProtectedRoute";
import { Layout }         from "../components/shared/Layout";

// ── Page imports ───────────────────────────────────────
import { LoginPage }     from "../features/auth/LoginPage";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { InventoryPage } from "../features/inventory/InventoryPage";
import { ScannerPage }   from "../features/scanner/ScannerPage";
import { ReportsPage }   from "../features/reports/ReportsPage";

// ── Unauthorized page (inline — no separate file needed) ──
const UnauthorizedPage = () => (
  <div
    style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "#0f1117",
      fontFamily: "system-ui",
      color: "#e2e8f0",
      flexDirection: "column",
      gap: 16,
      textAlign: "center",
      padding: 24,
    }}
  >
    <div className="text-5xl">🚫</div>
    <h1 className="text-xl font-bold">Access Denied</h1>
    <p className="text-sm text-muted-foreground">
      You don't have permission to view this page.
    </p>
      <a
      href="/"
      className="inline-block mt-4
        color: #00D4FF
        fontSize: 13
        textDecoration: none
        border: 1px solid #00D4FF40
        padding: 6px 16px
        borderRadius: 6
      ">
      ← Back to Dashboard
    </a>
  </div>
);


export const router = createBrowserRouter([

  // ── Public routes (no login needed) ───────────────────
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/unauthorized",
    element: <UnauthorizedPage />,
  },
  {
    // Catch-all: redirect unknown paths to dashboard
    path: "*",
    element: <Navigate to="/" replace />,
  },

  // ── Protected routes (any logged-in user) ─────────────
  {
    element: <ProtectedRoute />,
    children: [
      {
        element: <Layout />,
        children: [
          // Default route → Dashboard
          { index: true, element: <DashboardPage /> },
          { path: "/",          element: <DashboardPage /> },
          { path: "/inventory", element: <InventoryPage /> },
          { path: "/scanner",   element: <ScannerPage />   },
        ],
      },
    ],
  },

  // ── Admin-only routes ──────────────────────────────────
  {
    element: <ProtectedRoute allowedRoles={["admin"]} />,
    children: [
      {
        element: <Layout />,
        children: [
          { path: "/reports", element: <ReportsPage /> },
        ],
      },
    ],
  },
]);