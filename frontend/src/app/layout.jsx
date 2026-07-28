import "./NetShield.css";
import { ThemeProvider } from "../context/ThemeContext";

export const metadata = {
  title: "NetShield-AI",
  description: "Cybersecurity Enterprise SOC Security Gateway",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" data-theme="dark">
      <body>
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}