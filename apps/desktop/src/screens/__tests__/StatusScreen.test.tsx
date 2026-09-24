import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import StatusScreen from "../StatusScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    status: vi.fn(),
    listSessions: vi.fn(),
  },
}));

describe("StatusScreen", () => {
  it("renders status details when daemon is connected", async () => {
    vi.mocked(api.status).mockResolvedValue({
      device_fingerprint: "dev_1234567890abcdef",
      paired: true,
      core_bridge_reachable: true,
      active_session_count: 1,
      workspace_count: 2,
    });
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_1",
        remote_principal: "user@remote",
        status: "Active",
        capability_profile: "Design",
        task_scope: "General editing",
        expires_at: "2026-10-01T00:00:00Z",
      },
    ]);

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText("Connected")).toBeInTheDocument();
    });

    expect(screen.getByText("dev_1234567890abcdef")).toBeInTheDocument();
    expect(screen.getByText("Detected")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText(/1 active/i)).toBeInTheDocument();
  });

  it("renders disconnected state when daemon is unreachable", async () => {
    vi.mocked(api.status).mockRejectedValue("Connection refused");
    vi.mocked(api.listSessions).mockRejectedValue("Connection refused");

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText(/Daemon not reachable/i)).toBeInTheDocument();
    });

    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });
});
