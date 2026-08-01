import { redirect } from "next/navigation";
import { DeviceEnrollmentApproval } from "@/components/device-enrollment";
import { getCurrentUser, getTeams } from "@/lib/api";

export const dynamic = "force-dynamic";

type PageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

export default async function DevicePage({ searchParams }: PageProps) {
  const params = await searchParams;
  const rawCode = typeof params.user_code === "string" ? params.user_code : "";
  const initialCode = rawCode.slice(0, 12);
  const devicePath = initialCode
    ? `/device?user_code=${encodeURIComponent(initialCode)}`
    : "/device";
  const user = await getCurrentUser();
  if (!user) redirect(`/login?next=${encodeURIComponent(devicePath)}`);
  if (!user.organizationId) {
    redirect(`/organizations?next=${encodeURIComponent(devicePath)}`);
  }
  const teams = await getTeams();
  return (
    <DeviceEnrollmentApproval
      initialCode={initialCode}
      organizationName={user.organizationName ?? "Active workspace"}
      teams={teams}
    />
  );
}
