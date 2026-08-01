import { AcceptInvitationForm } from "@/components/identity-flows";
import { getAuthMethods } from "@/lib/auth-config";

export const dynamic = "force-dynamic";

export default async function AcceptInvitePage() {
  const methods = await getAuthMethods();
  return (
    <AcceptInvitationForm
      ssoEnabled={methods?.ssoEnabled ?? false}
      authConfigurationAvailable={methods !== null}
    />
  );
}
