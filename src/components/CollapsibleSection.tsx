import { useState, type ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';

type Accent = 'pink' | 'indigo' | 'amber' | 'cyan' | 'emerald' | 'neutral';

const accentBorder: Record<Accent, string> = {
  pink: 'border-l-pink-500',
  indigo: 'border-l-indigo-500',
  amber: 'border-l-amber-500',
  cyan: 'border-l-cyan-500',
  emerald: 'border-l-emerald-500',
  neutral: 'border-l-white/30',
};

const accentText: Record<Accent, string> = {
  pink: 'text-pink-300',
  indigo: 'text-indigo-300',
  amber: 'text-amber-300',
  cyan: 'text-cyan-300',
  emerald: 'text-emerald-300',
  neutral: 'text-white/70',
};

/**
 * Accordion block for panel sections.
 * Secondary chrome stays collapsed so each view is a calm vertical flow.
 */
export default function CollapsibleSection({
  title,
  subtitle,
  children,
  defaultOpen = false,
  accent = 'neutral',
  className = '',
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  defaultOpen?: boolean;
  accent?: Accent;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <details
      open={open}
      onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}
      className={`glass-card group border-l-2 ${accentBorder[accent]} overflow-hidden ${className}`}
    >
      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2 select-none [&::-webkit-details-marker]:hidden">
        <div className="min-w-0">
          <div className={`text-xs font-bold tracking-wider uppercase ${accentText[accent]}`}>
            {title}
          </div>
          {subtitle ? (
            <p className="mt-0.5 truncate text-[10px] text-white/40">{subtitle}</p>
          ) : null}
        </div>
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-white/40 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </summary>
      <div className="space-y-2.5 border-t border-white/5 px-3 py-3">{children}</div>
    </details>
  );
}
