import { LoginForm } from "@/components/auth";
import { getAuthMethods } from "@/lib/auth-config";
import { safeNextPath } from "@/lib/navigation";

export const dynamic = "force-dynamic";

type PageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

export default async function LoginPage({ searchParams }: PageProps) {
  const [methods, params] = await Promise.all([getAuthMethods(), searchParams]);
  const requestedNext = typeof params.next === "string" ? params.next : null;
  const nextPath = safeNextPath(requestedNext);
  const ssoError = typeof params.sso_error === "string" ? params.sso_error : null;
  return (
    <div className="auth-shell">
      <LoginForm methods={methods} nextPath={nextPath} ssoError={ssoError} />
    </div>
  );
}
