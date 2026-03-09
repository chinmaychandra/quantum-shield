import { apiClient } from './client';
import { Asset, ScanJob } from '../types';

// ─── AUTH ───────────────────────────────────────
export const authAPI = {
  login: (email: string, password: string) =>
    apiClient.post('/auth/login', { email, password }),

  logout: () =>
    apiClient.post('/auth/logout'),
};

// ─── INVENTORY ──────────────────────────────────
export const inventoryAPI = {
  getAll: () =>
    apiClient.get<Asset[]>('/inventory'),

  bulkUpload: (assets: Partial<Asset>[]) =>
    apiClient.post('/inventory/bulk', assets),
};

// ─── SCANNER ────────────────────────────────────
export const scannerAPI = {
  startScan: (target: string, depth: string) =>
    apiClient.post<ScanJob>('/scanner/start', { target, depth }),

  getScanHistory: () =>
    apiClient.get<ScanJob[]>('/scanner/history'),
};

// ─── REPORTS ────────────────────────────────────
export const reportsAPI = {
  downloadPDF: (scanId: string) =>
    apiClient.get(`/reports/${scanId}/pdf`, { responseType: 'blob' }),

  downloadJSON: (scanId: string) =>
    apiClient.get(`/reports/${scanId}/json`), 
};