import { redirect } from "next/navigation";

export default async function AdministratorSectionPage({ params }) {
  const { section } = await params;
  const lowerSection = section ? section.toLowerCase() : "dashboard";
  redirect(`/admin/${lowerSection}`);
}
