import {
  useReactTable, getCoreRowModel, getSortedRowModel,
  getFilteredRowModel, getPaginationRowModel,
  flexRender, ColumnDef, SortingState
} from '@tanstack/react-table';
import { useState } from 'react';
import { Asset } from '../../types';
import { RiskBadge } from '../../components/shared/RiskBadge';

// ── Column definitions ─────────────────────────
const columns: ColumnDef<Asset>[] = [
  { accessorKey: 'hostname', header: 'Hostname' },
  { accessorKey: 'ip', header: 'IP Address' },
  { accessorKey: 'tlsVersion', header: 'TLS Version' },
  {
    accessorKey: 'riskLevel',
    header: 'Risk Level',
    cell: ({ getValue }) => (
      <RiskBadge level={getValue() as any} />
    ),
  },
  {
    accessorKey: 'riskScore',
    header: 'Risk Score',
    cell: ({ getValue }) => (
      <span className="font-mono font-bold">
        {getValue() as number}
      </span>
    ),
  },
  { accessorKey: 'pqcStatus', header: 'PQC Status' },
  { accessorKey: 'lastScanned', header: 'Last Scanned' },
];

// ── Component ─────────────────────────────────
export const InventoryTable = ({ data }: { data: Asset[] }) => {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [globalFilter, setGlobalFilter] = useState('');

  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  });

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <input
        value={globalFilter}
        onChange={e => setGlobalFilter(e.target.value)}
        placeholder="Search all columns..."
        className="border px-3 py-2 rounded w-64 text-sm"
      />

      {/* Table */}
      <div className="overflow-x-auto rounded border">
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id}>
                {hg.headers.map(header => (
                  <th
                    key={header.id}
                    onClick={header.column.getToggleSortingHandler()}
                    className="px-4 py-3 text-left font-semibold cursor-pointer hover:bg-gray-100"
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                    {header.column.getIsSorted() === 'asc' ? ' ↑' :
                     header.column.getIsSorted() === 'desc' ? ' ↓' : ''}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => (
              <tr key={row.id} className="border-t hover:bg-gray-50">
                {row.getVisibleCells().map(cell => (
                  <td key={cell.id} className="px-4 py-3">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center gap-2 text-sm">
        <button onClick={() => table.previousPage()}
          disabled={!table.getCanPreviousPage()}
          className="px-3 py-1 border rounded disabled:opacity-40">← Prev</button>
        <span>Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}</span>
        <button onClick={() => table.nextPage()}
          disabled={!table.getCanNextPage()}
          className="px-3 py-1 border rounded disabled:opacity-40">Next →</button>
      </div>
    </div>
  );
};