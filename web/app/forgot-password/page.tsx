import { ForgotPasswordForm } from "@/components/identity-flows";
import { getAuthMethods } from "@/lib/auth-config";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function ForgotPasswordPage() {
  const methods = await getAuthMethods();
  if (!methods?.passwordEnabled) redirect("/login");
  return <ForgotPasswordForm />;
}
