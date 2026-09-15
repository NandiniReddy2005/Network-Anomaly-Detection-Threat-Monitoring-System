import { redirect } from "next/navigation";

export default function RootSettingsPage() {
  redirect("/admin/dashboard");
}
