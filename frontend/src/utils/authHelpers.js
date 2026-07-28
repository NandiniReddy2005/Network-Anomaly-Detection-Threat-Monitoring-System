export function getCurrentUser() {
  if (typeof window === "undefined") return null;
  const session = localStorage.getItem("netshield_current_user");
  return session ? JSON.parse(session) : null;
}

export function setCurrentUser(user) {
  if (typeof window === "undefined") return;
  if (user) {
    localStorage.setItem("netshield_current_user", JSON.stringify(user));
  } else {
    localStorage.removeItem("netshield_current_user");
  }
}

export function clearCurrentUser() {
  if (typeof window === "undefined") return;
  localStorage.removeItem("netshield_current_user");
}
