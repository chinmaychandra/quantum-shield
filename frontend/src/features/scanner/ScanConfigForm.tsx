import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useStartScan } from './hooks/useScanner';

// ── Validation schema ─────────────────────────
const scanSchema = z.object({
  target: z
    .string()
    .min(1, 'Target is required')
    .refine(
      val => /^(\d{1,3}\.){3}\d{1,3}$/.test(val) || /^https?:\/\//.test(val),
      'Enter a valid IP address or URL (http://...)'
    ),
  depth: z.enum(['shallow', 'standard', 'deep']).catch('standard'),
  ports: z
    .string()
    .regex(/^\d+([,-]\d+)*$/, 'Ports must be numbers, commas, or ranges (e.g. 80,443,8000-9000)')
    .optional(),
});

// TypeScript type auto-generated from schema
type ScanFormData = z.infer<typeof scanSchema>;

// ── Component ─────────────────────────────────
export const ScanConfigForm = () => {
  const { mutate: startScan, isPending } = useStartScan();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ScanFormData>({
    resolver: zodResolver(scanSchema),
    defaultValues: { depth: 'standard' },
  });

  const onSubmit = (data: ScanFormData) => {
    startScan({ target: data.target, depth: data.depth });
    reset();
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4 max-w-md">

      {/* Target field */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Target IP or URL
        </label>
        <input
          {...register('target')}
          placeholder="192.168.1.1 or https://example.com"
          className="w-full border rounded px-3 py-2 text-sm"
        />
        {errors.target && (
          <p className="text-red-500 text-xs mt-1">{errors.target.message}</p>
        )}
      </div>

      {/* Scan depth */}
      <div>
        <label className="block text-sm font-medium mb-1">Scan Depth</label>
        <select {...register('depth')} className="w-full border rounded px-3 py-2 text-sm">
          <option value="shallow">Shallow — fast overview</option>
          <option value="standard">Standard — recommended</option>
          <option value="deep">Deep — thorough (slow)</option>
        </select>
        {errors.depth && (
          <p className="text-red-500 text-xs mt-1">{errors.depth.message}</p>
        )}
      </div>

      {/* Ports field */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Ports <span className="text-gray-400">(optional)</span>
        </label>
        <input
          {...register('ports')}
          placeholder="80,443,8000-9000"
          className="w-full border rounded px-3 py-2 text-sm"
        />
        {errors.ports && (
          <p className="text-red-500 text-xs mt-1">{errors.ports.message}</p>
        )}
      </div>

      <button
        type="submit"
        disabled={isPending}
        className="w-full bg-blue-600 text-white py-2 rounded font-medium hover:bg-blue-700 disabled:opacity-50"
      >
        {isPending ? 'Starting scan...' : 'Start Scan'}
      </button>

    </form>
  );
};