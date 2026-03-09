import { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { useAuthStore } from '../store/authStore';
import { ScanStatus } from '../types';

interface ScanProgress {
  progress: number;        // 0–100
  status: ScanStatus;
  message: string;
}

export const useScanProgress = (scanId: string | null) => {
  const token = useAuthStore(state => state.token);
  const [data, setData] = useState<ScanProgress>({
    progress: 0,
    status: 'idle',
    message: '',
  });

  useEffect(() => {
    if (!scanId) return; // don't connect if no active scan

    // Connect to WebSocket server with JWT auth
    const socket = io(import.meta.env.VITE_WS_URL, {
      auth: { token },
    });

    // Tell server which scan to watch
    socket.emit('subscribe_scan', { scanId });

    // Listen for progress updates from server
    socket.on('scan_progress', ({ percent, message }) => {
      setData({ progress: percent, status: 'running', message });
    });

    // Listen for scan completion
    socket.on('scan_complete', () => {
      setData(prev => ({ ...prev, progress: 100, status: 'completed' }));
    });

    // Listen for errors
    socket.on('scan_error', ({ message }) => {
      setData(prev => ({ ...prev, status: 'failed', message }));
    });

    // Cleanup: disconnect when component unmounts
    return () => {
      socket.disconnect();
    };
  }, [scanId, token]);

  return data;
};

// ─── HOW TO USE IN A COMPONENT ──────────────────
// const { progress, status, message } = useScanProgress(activeScanId);
// <ProgressBar value={progress} />
// <StatusBadge status={status} />`
      