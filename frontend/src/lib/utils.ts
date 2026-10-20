import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function parseJWT(token: string): { sub?: string; exp?: number } | null {
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return null;
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

export function getClaimColor(claim: string): string {
  switch (claim) {
    case 'admin': return 'bg-red-100 text-[#991B1B] border-red-300';
    case 'deployer': return 'bg-purple-100 text-purple-700 border-purple-300';
    case 'upgrade': return 'bg-orange-100 text-orange-700 border-orange-300';
    case 'writer': return 'bg-blue-100 text-blue-700 border-blue-300';
    case 'reader': return 'bg-green-100 text-green-700 border-green-300';
    default: return 'bg-gray-100 text-gray-600 border-gray-300';
  }
}
