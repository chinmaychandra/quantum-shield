import React from "react";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  message?: string;
  fullPage?: boolean;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = "md",
  message = "Loading...",
  fullPage = false,
}) => {

  // Maps size prop → Tailwind classes
  const sizeMap = {
    sm: {
      outer: "w-7 h-7",
      ring:  "border-2",
      inner: "inset-1",
      dot:   "w-1.5 h-1.5",
    },
    md: {
      outer: "w-11 h-11",
      ring:  "border-2",
      inner: "inset-1.5",
      dot:   "w-2 h-2",
    },
    lg: {
      outer: "w-16 h-16",
      ring:  "border-[3px]",
      inner: "inset-2",
      dot:   "w-3 h-3",
    },
  };

  const s = sizeMap[size];

  return (
    <div
      className={[
        // Base layout
        "flex flex-col items-center justify-center gap-4 p-10",
        // Full page overlay (optional)
        fullPage
          ? "fixed inset-0 z-50 bg-[#0f1117]/80 backdrop-blur-sm"
          : "",
      ].join(" ")}
    >
      {/* Spinner container */}
      <div className={`relative flex items-center justify-center ${s.outer}`}>

        {/* Outer ring — spins clockwise */}
        <div
          className={[
            "absolute inset-0 rounded-full",
            "border-transparent",
            s.ring,
            "border-t-[#00D4FF]",
            "animate-spin",
          ].join(" ")}
          style={{ animationDuration: "0.85s" }}
        />

        {/* Inner ring — spins counter-clockwise */}
        <div
          className={[
            "absolute rounded-full",
            "border-transparent",
            s.inner,
            s.ring,
            "border-t-[#A855F7]",
            "animate-spin",
          ].join(" ")}
          style={{
            animationDuration: "1.2s",
            animationDirection: "reverse",
          }}
        />

        {/* Centre dot — pulses */}
        <div
          className={`${s.dot} rounded-full bg-[#00D4FF] animate-pulse`}
        />
      </div>

      {/* Optional message */}
      {message && (
        <p className="text-[13px] text-slate-500 tracking-wide m-0">
          {message}
        </p>
      )}
    </div>
  );
};