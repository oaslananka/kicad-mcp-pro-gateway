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
      data_dir: "/home/user/.local/share/kicad-mcp-gateway",
      log_level: "info",
      core_bridge_endpoint: "http://127.0.0.1:4444/mcp",
      transport_mode: "disabled",
    });

    render(<SettingsScreen />);

    expect(screen.getByText("Loading configuration...")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("/home/user/.local/share/kicad-mcp-gateway")).toBeInTheDocument();
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

  it("shows different log levels correctly", async () => {
    vi.mocked(api.getConfig).mockResolvedValueOnce({
      data_dir: "/home/user/.local/share/kicad-mcp-gateway",
      log_level: "trace",
      core_bridge_endpoint: "http://127.0.0.1:4444/mcp",
      transport_mode: "stdio",
    });

    render(<SettingsScreen />);

    await waitFor(() => {
      expect(screen.getByText("trace")).toBeInTheDocument();
    });

    expect(screen.getByText("stdio")).toBeInTheDocument();
  });

  it("shows different transport modes correctly", async () => {
    vi.mocked(api.getConfig).mockResolvedValueOnce({
      data_dir: "/home/user/.local/share/kicad-mcp-gateway",
      log_level: "debug",
      core_bridge_endpoint: "http://127.0.0.1:4444/mcp",
      transport_mode: "tcp",
    });

    render(<SettingsScreen />);

    await waitFor(() => {
      expect(screen.getByText("tcp")).toBeInTheDocument();
    });
  });

  it("displays configuration precedence order correctly", async () => {
    vi.mocked(api.getConfig).mockResolvedValueOnce({
      data_dir: "/home/user/.local/share/kicad-mcp-gateway",
      log_level: "info",
      core_bridge_endpoint: "http://127.0.0.1:4444/mcp",
      transport_mode: "disabled",
    });

    render(<SettingsScreen />);

    await waitFor(() => {
      expect(screen.getByText("Configuration Precedence")).toBeInTheDocument();
    });

    expect(screen.getByText("CLI flags")).toBeInTheDocument();
    expect(screen.getByText("Environment variables")).toBeInTheDocument();
    expect(screen.getByText("Configuration file")).toBeInTheDocument();
    expect(screen.getByText("Built-in defaults")).toBeInTheDocument();
    // config.toml appears twice (in list and hint), check for the list item specifically
    const configTomlElements = screen.getAllByText(/config\.toml/i);
    expect(configTomlElements.length).toBeGreaterThanOrEqual(1);
  });

  it("displays privacy and security policy invariants", async () => {
    vi.mocked(api.getConfig).mockResolvedValueOnce({
      data_dir: "/home/user/.local/share/kicad-mcp-gateway",
      log_level: "info",
      core_bridge_endpoint: "http://127.0.0.1:4444/mcp",
      transport_mode: "disabled",
    });

    render(<SettingsScreen />);

    await waitFor(() => {
      expect(screen.getByText("Privacy & Security Policy")).toBeInTheDocument();
    });

    // Text is split across elements, check for key phrases
    expect(screen.getByText(/Gateway telemetry is/i)).toBeInTheDocument();
    expect(screen.getByText(/off by default/i)).toBeInTheDocument();
    expect(screen.getByText(/Local core bridge remains restricted to loopback/i)).toBeInTheDocument();
    expect(screen.getByText(/Secrets and credentials are never stored in plaintext/i)).toBeInTheDocument();
    expect(screen.getByText(/Unknown tools default to fail-closed state/i)).toBeInTheDocument();
  });

  it("handles error without losing loading state", async () => {
    vi.mocked(api.getConfig).mockRejectedValueOnce("timeout");

    render(<SettingsScreen />);

    // Loading should show initially
    expect(screen.getByText("Loading configuration...")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/Error loading configuration:/i)).toBeInTheDocument();
    });

    // Loading should be gone
    expect(screen.queryByText("Loading configuration...")).not.toBeInTheDocument();
  });
});