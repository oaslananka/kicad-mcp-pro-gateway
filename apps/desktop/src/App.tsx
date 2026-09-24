import { useState } from "react";
import StatusScreen from "./screens/StatusScreen";
import DeviceScreen from "./screens/DeviceScreen";
import PairingScreen from "./screens/PairingScreen";
import WorkspacesScreen from "./screens/WorkspacesScreen";
import SessionsScreen from "./screens/SessionsScreen";
import ActivityScreen from "./screens/ActivityScreen";
import SettingsScreen from "./screens/SettingsScreen";

const TABS = [
  { id: "status", label: "Status", component: StatusScreen },
  { id: "device", label: "Device", component: DeviceScreen },
  { id: "pairing", label: "Pairing", component: PairingScreen },
  { id: "workspaces", label: "Workspaces", component: WorkspacesScreen },
  { id: "sessions", label: "Sessions", component: SessionsScreen },
  { id: "activity", label: "Activity", component: ActivityScreen },
  { id: "settings", label: "Settings", component: SettingsScreen },
] as const;

type TabId = (typeof TABS)[number]["id"];

export default function App() {
  const [active, setActive] = useState<TabId>("status");
  const ActiveComponent = TABS.find((t) => t.id === active)?.component ?? StatusScreen;

  return (
    <div className="app">
      <nav className="nav">
        <h1>KiCad MCP Pro Gateway</h1>
        {TABS.map((tab) => (
          <button key={tab.id} className={tab.id === active ? "active" : ""} onClick={() => setActive(tab.id)}>
            {tab.label}
          </button>
        ))}
      </nav>
      <main className="content">
        <ActiveComponent />
      </main>
    </div>
  );
}
