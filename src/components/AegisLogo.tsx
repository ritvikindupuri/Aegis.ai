import { useId } from "react";

interface AegisLogoProps {
  className?: string;
  /** Simplified badge (no "!") for very small sizes, e.g. 16-24px. */
  compact?: boolean;
}

/**
 * AEGIS.ai mark: a violet shield holding code brackets around an AI spark
 * (AI-generated fixes), with an amber alert badge on the top-right edge
 * (live NVD / CISA KEV exploited-CVE enrichment).
 */
const AegisLogo = ({ className, compact = false }: AegisLogoProps) => {
  const uid = useId().replace(/:/g, "");
  const gradientId = `aegis-shield-${uid}`;
  const maskId = `aegis-badge-cut-${uid}`;
  const badgeR = compact ? 10 : 8.5;
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      fill="none"
      className={className}
      role="img"
      aria-label="AEGIS.ai"
    >
      <defs>
        <linearGradient id={gradientId} x1="12" y1="4" x2="52" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#8B6CFF" />
          <stop offset="1" stopColor="#5B3FE0" />
        </linearGradient>
        <mask id={maskId} maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">
          <rect width="64" height="64" fill="#fff" />
          <circle cx="50" cy="14" r={badgeR + 3} fill="#000" />
        </mask>
      </defs>
      <g mask={`url(#${maskId})`}>
        <path
          d="M32 5 53 12.5V30c0 13.6-8.9 24-21 29C19.9 54 11 43.6 11 30V12.5Z"
          fill={`url(#${gradientId})`}
          stroke={`url(#${gradientId})`}
          strokeWidth="2"
          strokeLinejoin="round"
        />
        <path
          d="M22.5 25 16.5 32l6 7M41.5 25l6 7-6 7"
          stroke="#fff"
          strokeWidth="4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M32 24.5c.9 4.6 2.9 6.6 7.5 7.5-4.6.9-6.6 2.9-7.5 7.5-.9-4.6-2.9-6.6-7.5-7.5 4.6-.9 6.6-2.9 7.5-7.5Z"
          fill="#fff"
        />
      </g>
      <circle cx="50" cy="14" r={badgeR} fill="#F59E0B" />
      {!compact && (
        <>
          <path d="M50 9.6v5.2" stroke="#1C1917" strokeWidth="2.6" strokeLinecap="round" />
          <circle cx="50" cy="18.6" r="1.45" fill="#1C1917" />
        </>
      )}
    </svg>
  );
};

export default AegisLogo;
