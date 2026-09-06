import { Moon, Sun, Monitor } from 'lucide-react';
import { useTheme, ThemePreference } from '@/contexts/ThemeContext';
import { cn } from '@/lib/utils';

const options: { value: ThemePreference; icon: typeof Sun; label: string }[] = [
  { value: 'light', icon: Sun, label: 'Light' },
  { value: 'dark', icon: Moon, label: 'Dark' },
  { value: 'system', icon: Monitor, label: 'System' },
];

interface ThemeToggleProps {
  /** "segmented" shows all three options; "icon" is a single-button toggle. */
  variant?: 'segmented' | 'icon';
  className?: string;
}

export const ThemeToggle = ({ variant = 'segmented', className }: ThemeToggleProps) => {
  const { preference, resolved, toggle, setPreference } = useTheme();

  if (variant === 'icon') {
    const Icon = resolved === 'dark' ? Moon : Sun;
    return (
      <button
        type="button"
        onClick={toggle}
        aria-label={resolved === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        className={cn(
          'inline-flex h-9 w-9 items-center justify-center rounded-md border border-border bg-card text-muted-foreground transition-colors hover:bg-accent hover:text-foreground',
          className
        )}
      >
        <Icon className="h-4 w-4" />
      </button>
    );
  }

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      className={cn(
        'inline-flex items-center gap-0.5 rounded-md border border-border bg-card p-0.5',
        className
      )}
    >
      {options.map((opt) => {
        const Icon = opt.icon;
        const active = preference === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            title={opt.label}
            onClick={() => setPreference(opt.value)}
            className={cn(
              'inline-flex h-7 w-7 items-center justify-center rounded text-muted-foreground transition-colors',
              active
                ? 'bg-primary/15 text-primary'
                : 'hover:bg-accent hover:text-foreground'
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            <span className="sr-only">{opt.label}</span>
          </button>
        );
      })}
    </div>
  );
};
