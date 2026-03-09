import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scannerAPI } from '../../../api/endpoints';

// FETCH scan history
export const useScanHistory = () => {
  return useQuery({
    queryKey: ['scan-history'],
    queryFn: () => scannerAPI.getScanHistory().then(res => res.data),
  });
};

// START a new scan
export const useStartScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ target, depth }: { target: string; depth: string }) =>
      scannerAPI.startScan(target, depth).then(res => res.data),

    onSuccess: () => {
      // Refresh scan history after starting new scan
      queryClient.invalidateQueries({ queryKey: ['scan-history'] });
    },
  });
};