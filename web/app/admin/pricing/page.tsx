import { redirect } from "next/navigation";
import { PricingManager } from "@/components/pricing";
import { getCurrentUser, getPrices } from "@/lib/api";
import { UnavailablePanel } from "@/app/page";

export const dynamic = "force-dynamic";

export default async function PricingPage() {
  const user = await getCurrentUser();
  if (!user) redirect("/login");
  if (!user.organizationId) redirect("/organizations?next=/admin/pricing");
  if (user.role !== "admin") return <UnavailablePanel message="Only organization administrators can manage pricing." />;
  const prices = await getPrices();
  return <PricingManager prices={prices} />;
}
