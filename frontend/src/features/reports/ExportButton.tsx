import { saveAs } from 'file-saver';
import { reportsAPI } from '../../api/endpoints';
import { useState } from 'react';

interface Props {
  scanId: string;
}

export const ExportButton = ({ scanId }: Props) => {
  const [loading, setLoading] = useState<'pdf' | 'json' | null>(null);

  // Download PDF from server as blob
  const downloadPDF = async () => {
    setLoading('pdf');
    try {
      const { data } = await reportsAPI.downloadPDF(scanId);
      saveAs(data, `qps-report-${scanId}.pdf`);
    } catch {
      alert('PDF download failed');
    } finally {
      setLoading(null);
    }
  };

  // Download JSON (client-side generation)
  const downloadJSON = async () => {
    setLoading('json');
    try {
      const { data } = await reportsAPI.downloadJSON(scanId);
      const blob = new Blob(
        [JSON.stringify(data, null, 2)],
        { type: 'application/json' }
      );
      saveAs(blob, `qps-report-${scanId}.json`);
    } catch {
      alert('JSON download failed');
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="flex gap-2">
      <button
        onClick={downloadPDF}
        disabled={!!loading}
        className="px-4 py-2 bg-red-50 text-red-700 border border-red-200 rounded text-sm hover:bg-red-100 disabled:opacity-50"
      >
        {loading === 'pdf' ? 'Downloading...' : '📄 Export PDF'}
      </button>

      <button
        onClick={downloadJSON}
        disabled={!!loading}
        className="px-4 py-2 bg-blue-50 text-blue-700 border border-blue-200 rounded text-sm hover:bg-blue-100 disabled:opacity-50"
      >
        {loading === 'json' ? 'Downloading...' : '{ } Export JSON'}
      </button>
    </div>
  );
};