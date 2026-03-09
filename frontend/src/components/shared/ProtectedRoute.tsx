import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import { UserRole } from '../../types';

interface Props {
  allowedRoles?: UserRole[];
}

export const ProtectedRoute = ({ allowedRoles }: Props) => {
  const { token, role } = useAuthStore();

  // Not logged in → go to login page
  if (!token) {
    return <Navigate to="/login" replace />;
  }

  // Logged in but wrong role → go to unauthorized page
  if (allowedRoles && role && !allowedRoles.includes(role)) {
    return <Navigate to="/unauthorized" replace />;
  }

  // All good → render the child page
  return <Outlet />;
}