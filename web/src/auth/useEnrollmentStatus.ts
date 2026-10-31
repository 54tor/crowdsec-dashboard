import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'

export const ENROLLMENT_STATUS_QUERY_KEY = ['enrollment-status']

interface EnrollmentStatus {
  enrollment_required: boolean
}

export function useEnrollmentStatus() {
  const statusQuery = useQuery({
    queryKey: ENROLLMENT_STATUS_QUERY_KEY,
    queryFn: () => apiFetch<EnrollmentStatus>('/api/auth/status'),
    gcTime: 0,
  })
  return {
    isPending: statusQuery.isPending,
    isEnrollmentRequired: statusQuery.data?.enrollment_required === true,
  }
}
