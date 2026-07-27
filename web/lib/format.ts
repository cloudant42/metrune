const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const money = new Intl.NumberFormat("en", { style: "currency", currency: "USD" });

export function formatCompact(value: number) {
  return compact.format(value);
}

export function formatMoney(value: number) {
  return money.format(value);
}

export function label(value: string) {
  if (!value) return "Unassigned";
  return value.split("_").map(part => part[0]?.toUpperCase() + part.slice(1)).join(" ");
}

export function shortModel(model: string) {
  return model.includes("/") ? model.split("/").slice(1).join("/") : model;
}

export function formatTime(ms: number) {
  return new Date(ms).toLocaleString("en", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
