"use client";

import { useEffect, useState } from "react";
import { MonitorIcon, MoonIcon, SunIcon } from "./icons";

export type Theme = "light" | "dark" | "system";

const storageKey = "metrune-theme";

/* Stamps the stored theme on <html> before first paint so a dark reload never
   flashes the light surface. Kept in sync with `apply` below. */
export function ThemeScript() {
  const script = `try{var t=localStorage.getItem("${storageKey}");if(t==="light"||t==="dark"){document.documentElement.dataset.theme=t}}catch(e){}`;
  return <script dangerouslySetInnerHTML={{ __html: script }} />;
}

function apply(theme: Theme) {
  const root = document.documentElement;
  if (theme === "system") delete root.dataset.theme;
  else root.dataset.theme = theme;
}

export function ThemeSwitch() {
  const [theme, setTheme] = useState<Theme>("system");

  useEffect(() => {
    const stored = localStorage.getItem(storageKey);
    if (stored === "light" || stored === "dark") setTheme(stored);
  }, []);

  function choose(next: Theme) {
    setTheme(next);
    apply(next);
    if (next === "system") localStorage.removeItem(storageKey);
    else localStorage.setItem(storageKey, next);
  }

  const options: { value: Theme; label: string; icon: React.ReactNode }[] = [
    { value: "light", label: "Light", icon: <SunIcon /> },
    { value: "dark", label: "Dark", icon: <MoonIcon /> },
    { value: "system", label: "Auto", icon: <MonitorIcon /> },
  ];

  return (
    <div className="theme-switch" role="group" aria-label="Color theme">
      {options.map(option => (
        <button key={option.value} type="button" aria-pressed={theme === option.value} onClick={() => choose(option.value)} title={`${option.label} theme`}>
          {option.icon}{option.label}
        </button>
      ))}
    </div>
  );
}
