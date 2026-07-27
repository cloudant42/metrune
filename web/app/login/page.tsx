import { LoginForm } from "@/components/auth";

export const dynamic = "force-dynamic";

export default function LoginPage() {
  return <div className="auth-shell"><LoginForm /></div>;
}
