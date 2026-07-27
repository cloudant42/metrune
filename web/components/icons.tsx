type IconProps = { size?: number };

export function MarkIcon({ size = 22 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><path d="M4 18V9l4 5 4-9 4 9 4-5v9" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}
export function OverviewIcon({ size = 18 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.8"/><rect x="14" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.8"/><rect x="3" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.8"/><rect x="14" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.8"/></svg>;
}
export function UsageIcon({ size = 18 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><path d="M4 19V9m5 10V5m6 14v-7m5 7V8" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/></svg>;
}
export function CategoryIcon({ size = 18 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.8"/><path d="M12 3v9l6.5 6.2" stroke="currentColor" strokeWidth="1.8"/></svg>;
}
export function TeamIcon({ size = 18 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><circle cx="9" cy="8" r="3" stroke="currentColor" strokeWidth="1.8"/><circle cx="17" cy="9" r="2" stroke="currentColor" strokeWidth="1.8"/><path d="M3.5 20c.5-4 2.3-6 5.5-6s5 2 5.5 6M14 15c3.5-.5 5.5 1.2 6 4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/></svg>;
}
export function TableIcon({ size = 18 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" strokeWidth="1.8"/><path d="M3 9.5h18M3 14.5h18M9.5 9.5V20" stroke="currentColor" strokeWidth="1.8"/></svg>;
}
export function UserIcon({ size = 18 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="4" stroke="currentColor" strokeWidth="1.8"/><path d="M4.5 21c.7-5 3.2-7.5 7.5-7.5s6.8 2.5 7.5 7.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/></svg>;
}
export function SettingsIcon({ size = 18 }: IconProps) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.8"/><path d="M19 13.5v-3l-2-.6a7 7 0 0 0-.8-1.8l1-1.9-2.2-2.1-1.8 1a7 7 0 0 0-2-.8L10.5 2h-3L7 4.3a7 7 0 0 0-1.9.8l-2-1L1 6.2l1.1 1.9a7 7 0 0 0-.8 1.8l-2 .6v3l2 .6a7 7 0 0 0 .8 1.8L1 17.8l2.1 2.1 2-1a7 7 0 0 0 1.9.8l.5 2.3h3l.7-2.3a7 7 0 0 0 2-.8l1.8 1 2.2-2.1-1-1.9a7 7 0 0 0 .8-1.8l2-.6Z" transform="translate(2)" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/></svg>;
}
