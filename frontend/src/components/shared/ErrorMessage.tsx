import React from "react";

interface ErrorMessageProps {
  message?: string;
  title?: string;
  onRetry?: () => void;
  fullPage?: boolean;
  type?: "error" | "warning" | "empty";
}

export const ErrorMessage: React.FC<ErrorMessageProps> = ({
  message = "Something went wrong. Please try again.",
  title,
  onRetry,
  fullPage = false,
  type = "error",
}) => {

  // Maps type prop → all Tailwind colour classes
  const typeMap = {
    error: {
      icon:         "✗",
      defaultTitle: "Failed to load data",
      ringBg:       "bg-red-500/10",
      ringBorder:   "border-red-500/40",
      iconColor:    "text-red-400",
      titleColor:   "text-red-300",
    },
    warning: {
      icon:         "⚠",
      defaultTitle: "Warning",
      ringBg:       "bg-amber-500/10",
      ringBorder:   "border-amber-500/40",
      iconColor:    "text-amber-400",
      titleColor:   "text-amber-300",
    },
    empty: {
      icon:         "○",
      defaultTitle: "No data found",
      ringBg:       "bg-slate-500/10",
      ringBorder:   "border-slate-500/40",
      iconColor:    "text-slate-400",
      titleColor:   "text-slate-400",
    },
  };

  const t = typeMap[type];

  return (
    <div
      className={[
        // Base layout
        "flex flex-col items-center justify-center",
        "gap-3 px-6 py-10 text-center",
        // Full page override (optional)
        fullPage ? "fixed inset-0 z-50 bg-[#0f1117]" : "",
      ].join(" ")}
    >
      {/* Icon ring — colour changes per type */}
      <div
        className={[
          "w-14 h-14 rounded-full",
          "flex items-center justify-center",
          "border",
          t.ringBg,
          t.ringBorder,
        ].join(" ")}
      >
        <span className={`text-xl not-italic ${t.iconColor}`}>
          {t.icon}
        </span>
      </div>

      {/* Title + message */}
      <div className="flex flex-col gap-1">
        <h3 className={`text-sm font-semibold m-0 ${t.titleColor}`}>
          {title || t.defaultTitle}
        </h3>
        <p className="text-xs text-slate-500 m-0 leading-relaxed max-w-xs">
          {message}
        </p>
      </div>

      {/* Retry button — only shown when onRetry prop is passed */}
      {onRetry && (
        <button
          onClick={onRetry}
          className={[
            "mt-1 px-5 py-1.5 rounded-md",
            "text-xs font-semibold tracking-wide",
            "border border-[#00D4FF]/30",
            "bg-[#00D4FF]/[0.08]",
            "text-[#00D4FF]",
            "hover:bg-[#00D4FF]/[0.15]",
            "hover:border-[#00D4FF]/50",
            "transition-all duration-150",
            "cursor-pointer",
          ].join(" ")}
        >
          ↺ Retry
        </button>
      )}
    </div>
  );
};