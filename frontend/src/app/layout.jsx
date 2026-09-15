import "./NetShield.css";
import { ThemeProvider } from "../context/ThemeContext";
import { IncidentProvider } from "../context/IncidentContext";

export const metadata = {
  title: "NetShield-AI",
  description: "Cybersecurity Enterprise SOC Security Gateway",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" data-theme="dark">
      <body>
        <ThemeProvider>
          <IncidentProvider>{children}</IncidentProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}