import { redirect } from "next/navigation";
import { WorkspaceChooser } from "@/components/organizations";
import { getCurrentUser } from "@/lib/api";
import { safeNextPath } from "@/lib/navigation";

export const dynamic = "force-dynamic";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function OrganizationsPage({ searchParams }: PageProps) {
  const params = await searchParams;
  const requested = typeof params.next === "string" ? params.next : "/";
  const next = safeNextPath(requested) ?? "/";
  const user = await getCurrentUser();
  if (!user) redirect("/login");
  return <WorkspaceChooser user={user} next={next} />;
}
