import { AdminTabs } from "@/components/admin";
import { getAdminData, getCurrentUser, type PageParams } from "@/lib/api";
import { toParams, UnavailablePanel } from "../page";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function AdminPage({ searchParams }: PageProps) {
  const params: PageParams = await toParams(await searchParams);
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/admin");
  if (!user.organizationId) redirect("/organizations?next=/admin");
  if (user.role !== "admin") {
    return <UnavailablePanel message="Only organization administrators can open administration." />;
  }
  const data = await getAdminData();
  if (!data) return <UnavailablePanel />;
  return <AdminTabs data={data} initialTab={params.tab} />;
}
