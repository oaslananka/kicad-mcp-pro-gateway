import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import SettingsScreen from "../SettingsScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    getConfig: vi.fn(),
  },
}));

describe("SettingsScreen", () => {
  it("renders configuration details when loaded successfully", async () => {
    vi.mocked(api.getConfig).mockResolvedValueOnce({
      data_dir: "/home/user/.local/share/kicad-mcp-companion",
      log_level: "info",
      core_bridge_endpoint: "http://127.0.0.1:4444/mcp",
      transport_mode: "disabled",
    });

    render(<SettingsScreen />);

    expect(screen.getByText("Loading configuration...")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("/home/user/.local/share/kicad-mcp-companion")).toBeInTheDocument();
    });

    expect(screen.getByText("info")).toBeInTheDocument();
    expect(screen.getByText("http://127.0.0.1:4444/mcp")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
    expect(screen.getByText("Configuration Precedence")).toBeInTheDocument();
    expect(screen.getByText("Privacy & Security Policy")).toBeInTheDocument();
  });

  it("renders error message when config loading fails", async () => {
    vi.mocked(api.getConfig).mockRejectedValueOnce("daemon IPC connection refused");

    render(<SettingsScreen />);

    await waitFor(() => {
      expect(screen.getByText(/Error loading configuration:/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/daemon IPC connection refused/i)).toBeInTheDocument();
  });
});
