import { AdminTabs } from "@/components/admin";
import { getAdminData, type PageParams } from "@/lib/api";
import { DemoBanner, toParams } from "../page";

export const dynamic = "force-dynamic";

type PageProps = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function AdminPage({ searchParams }: PageProps) {
  const params: PageParams = await toParams(await searchParams);
  const { data, source } = await getAdminData();
  return (
    <>
      {source === "demo" && <DemoBanner />}
      <AdminTabs data={data} initialTab={params.tab} />
    </>
  );
}
