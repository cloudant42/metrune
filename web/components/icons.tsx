type IconProps = { size?: number };

/* One consistent set: 24px grid, 1.75 stroke, round caps and joins. */
function Icon({ size = 18, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      {children}
    </svg>
  );
}

/* The Metrune mark: a tall navy peak with the electric-blue peak beside it.
   It is the one two-tone icon in the set, so it draws its own colors. */
export function MarkIcon({ size = 18 }: IconProps) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"
      strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="miter">
      <path d="M3 17.2 8.4 3.6 13.4 20.4" stroke="var(--mark-deep)" />
      <path d="M12.2 17.6 16.6 7.4 21 17.6" stroke="var(--mark-bright)" />
    </svg>
  );
}
export function OverviewIcon({ size = 18 }: IconProps) {
  return <Icon size={size}><path d="M4 13h4v7H4zM10 8h4v12h-4zM16 4h4v16h-4z" /></Icon>;
}
export function UsageIcon({ size = 18 }: IconProps) {
  return <Icon size={size}><path d="M4 19h16" /><path d="M6.5 15.5 10 11l3.2 3 4.3-6" /></Icon>;
}
export function CategoryIcon({ size = 18 }: IconProps) {
  return <Icon size={size}><path d="M12 3a9 9 0 1 0 9 9h-9V3Z" /><path d="M15.5 3.9A9 9 0 0 1 20.1 8.5" /></Icon>;
}
export function TableIcon({ size = 18 }: IconProps) {
  return <Icon size={size}><rect x="3.5" y="4.5" width="17" height="15" rx="2.5" /><path d="M3.5 9.5h17M9.5 9.5v10" /></Icon>;
}
export function TeamIcon({ size = 18 }: IconProps) {
  return <Icon size={size}><circle cx="9.5" cy="8" r="3.2" /><path d="M3.5 19.5c.6-3.5 2.8-5.3 6-5.3s5.4 1.8 6 5.3" /><path d="M16 5.4a3 3 0 0 1 0 5.6M17.6 14.6c1.9.6 3 2.1 3.4 4.4" /></Icon>;
}
export function UserIcon({ size = 18 }: IconProps) {
  return <Icon size={size}><circle cx="12" cy="8" r="3.6" /><path d="M4.8 20c.8-4.2 3.3-6.3 7.2-6.3s6.4 2.1 7.2 6.3" /></Icon>;
}
export function SettingsIcon({ size = 18 }: IconProps) {
  return <Icon size={size}><circle cx="12" cy="12" r="2.8" /><path d="M19.4 14.5a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1v.3a2 2 0 1 1-4 0v-.2a1.6 1.6 0 0 0-2.8-1.1l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H3.4a2 2 0 1 1 0-4h.2a1.6 1.6 0 0 0 1.1-2.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 2.7-1.1V3.4a2 2 0 1 1 4 0v.2a1.6 1.6 0 0 0 2.8 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0 1.1 2.7h.3a2 2 0 1 1 0 4h-.2a1.6 1.6 0 0 0-1.5 1.1Z" /></Icon>;
}
export function SunIcon({ size = 15 }: IconProps) {
  return <Icon size={size}><circle cx="12" cy="12" r="4" /><path d="M12 2.5v2M12 19.5v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M2.5 12h2M19.5 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4" /></Icon>;
}
export function MoonIcon({ size = 15 }: IconProps) {
  return <Icon size={size}><path d="M20 14.3A8.2 8.2 0 0 1 9.7 4a8.5 8.5 0 1 0 10.3 10.3Z" /></Icon>;
}
export function MonitorIcon({ size = 15 }: IconProps) {
  return <Icon size={size}><rect x="3" y="4.5" width="18" height="12" rx="2" /><path d="M9 20h6M12 16.5V20" /></Icon>;
}
export function ChevronIcon({ size = 15 }: IconProps) {
  return <Icon size={size}><path d="m7 9.5 5 5 5-5" /></Icon>;
}
export function ArrowRightIcon({ size = 14 }: IconProps) {
  return <Icon size={size}><path d="M5 12h13M13 6.5 18.5 12 13 17.5" /></Icon>;
}
export function LogoutIcon({ size = 16 }: IconProps) {
  return <Icon size={size}><path d="M14.5 4.5H18a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2h-3.5" /><path d="M10 8.5 13.5 12 10 15.5M13 12H4" /></Icon>;
}
