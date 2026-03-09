import Papa from 'papaparse';
import { useRef } from 'react';
import { apiClient } from '../../api/client';

export const BulkUpload = () => {
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    Papa.parse(file, {
      header: true,           // first row = column names
      skipEmptyLines: true,
      complete: async ({ data, errors }) => {
        if (errors.length) {
          alert('CSV has errors: ' + errors[0].message);
          return;
        }

        try {
          await apiClient.post('/inventory/bulk', data);
          alert(`✓ Uploaded ${data.length} assets successfully`);
        } catch {
          alert('Upload failed. Check your CSV format.');
        }
      },
    });

    // Reset input so same file can be re-uploaded
    e.target.value = '';
  };

  return (
    <div>
      <input
        ref={inputRef}
        type="file"
        accept=".csv"
        onChange={handleFile}
        className="hidden"
        title="Upload CSV file"
      />
      <button
        onClick={() => inputRef.current?.click()}
        className="px-4 py-2 bg-gray-100 border rounded text-sm hover:bg-gray-200"
      >
        📂 Upload CSV
      </button>
      <p className="text-xs text-gray-500 mt-1">
        CSV must have headers: hostname, ip, tlsVersion, riskLevel
      </p>
    </div>
  );
};