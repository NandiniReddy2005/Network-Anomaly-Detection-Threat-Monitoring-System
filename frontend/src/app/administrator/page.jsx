import { redirect } from "next/navigation";

export default function AdministratorRootPage() {
  redirect("/admin/dashboard");
}
