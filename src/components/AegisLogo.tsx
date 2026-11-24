import { useId } from "react";

interface AegisLogoProps {
  className?: string;
}

/**
 * AEGIS.ai mark: a shield (protection) holding code brackets around a check,
 * for code and repo scanning that ends in verified fixes.
 */
const AegisLogo = ({ className }: AegisLogoProps) => {
  const gradientId = `aegis-shield-${useId().replace(/:/g, "")}`;
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
      </defs>
      <path
        d="M32 5 53 12.5V30c0 13.6-8.9 24-21 29C19.9 54 11 43.6 11 30V12.5Z"
        fill={`url(#${gradientId})`}
        stroke={`url(#${gradientId})`}
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M23.5 24.5 17 32l6.5 7.5M40.5 24.5 47 32l-6.5 7.5"
        stroke="#fff"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="m27 32.5 3.6 3.6L37.2 28" stroke="#fff" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
};

export default AegisLogo;
