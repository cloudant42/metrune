import { redirect } from "next/navigation";
import { WorkspaceChooser } from "@/components/organizations";
import { getCurrentUser } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function OrganizationsPage() {
  const user = await getCurrentUser();
  if (!user) redirect("/login");
  return <WorkspaceChooser user={user} />;
}
