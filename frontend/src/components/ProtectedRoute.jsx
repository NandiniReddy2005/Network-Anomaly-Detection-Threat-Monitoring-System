"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getCurrentUser } from "../utils/authHelpers";
import LoadingSpinner from "./LoadingSpinner";

export default function ProtectedRoute({ allowedRoles = [], children }) {
  const router = useRouter();
  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    const user = getCurrentUser();
    if (!user) {
      router.push("/login");
      return;
    }

    if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
      if (user.role === "analyst") {
        router.push("/analyst");
      } else if (user.role === "admin") {
        router.push("/admin");
      } else {
        router.push("/login");
      }
      return;
    }

    setAuthorized(true);
  }, [router, allowedRoles]);

  if (!authorized) {
    return <LoadingSpinner text="Verifying authentication & security clearance..." />;
  }

  return children;
}
