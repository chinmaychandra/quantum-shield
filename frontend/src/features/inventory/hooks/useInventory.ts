import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { inventoryAPI } from '../../../api/endpoints';
import { Asset } from '../../../types';

// FETCH all inventory assets
export const useInventory = () => {
  return useQuery({
    queryKey: ['inventory'],
    queryFn: () => inventoryAPI.getAll().then(res => res.data),
  });
};

// UPDATE a single asset (auto-refreshes the list after save)
export const useUpdateAsset = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (asset: Partial<Asset>) =>
      inventoryAPI.bulkUpload([asset]),

    // After successful save, refresh inventory list
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['inventory'] });
    },
  });
}