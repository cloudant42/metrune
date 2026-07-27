import { redirect } from "next/navigation";
import { PricingManager } from "@/components/pricing";
import { getCurrentUser, getPrices } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function PricingPage() {
  const user = await getCurrentUser();
  if (!user) redirect("/login");
  const prices = await getPrices();
  return <PricingManager prices={prices} />;
}
