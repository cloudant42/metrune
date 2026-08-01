import { semanticCategoryLabel } from "./semantic-categories";

const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const money = new Intl.NumberFormat("en", { style: "currency", currency: "USD" });
const dateTime = new Intl.DateTimeFormat("en", {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  timeZone: "UTC",
  timeZoneName: "short",
});
const date = new Intl.DateTimeFormat("en", {
  month: "short",
  day: "numeric",
  timeZone: "UTC",
});

export function formatCompact(value: number) {
  return compact.format(value);
}

export function formatMoney(value: number) {
  return money.format(value);
}

export function label(value: string) {
  if (!value) return "Unassigned";
  const category = semanticCategoryLabel(value);
  if (category) return category;
  return value.split("_").map(part => part[0]?.toUpperCase() + part.slice(1)).join(" ");
}

export function shortModel(model: string) {
  return model.includes("/") ? model.split("/").slice(1).join("/") : model;
}

export function formatTime(ms: number) {
  return dateTime.format(new Date(ms));
}

export function formatDate(ms: number) {
  return date.format(new Date(ms));
}
