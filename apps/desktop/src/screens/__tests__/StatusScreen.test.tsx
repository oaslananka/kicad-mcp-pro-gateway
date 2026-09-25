import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import StatusScreen from "../StatusScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    daemonLifecycle: vi.fn(),
    status: vi.fn(),
    listSessions: vi.fn(),
  },
}));

describe("StatusScreen", () => {
  it("renders status details when daemon is connected", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "ready",
      message: null,
      identity: {
        product_id: "kicad-mcp-gateway",
        protocol_version: 1,
        daemon_version: "0.1.0",
        instance_id: "instance-1",
      },
    });
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
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "failed",
      message: "packaged daemon is missing",
      identity: null,
    });
    vi.mocked(api.status).mockRejectedValue("Connection refused");
    vi.mocked(api.listSessions).mockRejectedValue("Connection refused");

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText(/Daemon not reachable/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/packaged daemon is missing/i)).toBeInTheDocument();
    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });

  it("distinguishes an explicit CLI stop from a startup failure", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "stopped",
      message: "stopped explicitly from the CLI",
      identity: null,
    });
    vi.mocked(api.status).mockRejectedValue("daemon stopped");
    vi.mocked(api.listSessions).mockRejectedValue("daemon stopped");

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText(/stopped explicitly from the CLI/i)).toBeInTheDocument();
    });
    expect(screen.getByText("Stopped")).toBeInTheDocument();
    expect(screen.queryByText(/failed to start/i)).not.toBeInTheDocument();
  });

  it("shows Starting state when daemon is starting", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "starting",
      message: null,
      identity: null,
    });
    vi.mocked(api.status).mockRejectedValue("not ready");
    vi.mocked(api.listSessions).mockRejectedValue("not ready");

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText("Starting")).toBeInTheDocument();
    });
  });

  it("shows core bridge as Offline when unreachable", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "ready",
      message: null,
      identity: {
        product_id: "kicad-mcp-gateway",
        protocol_version: 1,
        daemon_version: "0.1.0",
        instance_id: "instance-1",
      },
    });
    vi.mocked(api.status).mockResolvedValue({
      device_fingerprint: "dev_123",
      paired: true,
      core_bridge_reachable: false,
      active_session_count: 0,
      workspace_count: 1,
    });
    vi.mocked(api.listSessions).mockResolvedValue([]);

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText("Offline")).toBeInTheDocument();
    });
    expect(screen.getByText("Connected")).toBeInTheDocument();
  });

  it("shows no active sessions when list is empty", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "ready",
      message: null,
      identity: {
        product_id: "kicad-mcp-gateway",
        protocol_version: 1,
        daemon_version: "0.1.0",
        instance_id: "instance-1",
      },
    });
    vi.mocked(api.status).mockResolvedValue({
      device_fingerprint: "dev_123",
      paired: true,
      core_bridge_reachable: true,
      active_session_count: 0,
      workspace_count: 0,
    });
    vi.mocked(api.listSessions).mockResolvedValue([]);

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText("None")).toBeInTheDocument();
    });
  });

  it("shows device fingerprint as not created yet when null", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "ready",
      message: null,
      identity: {
        product_id: "kicad-mcp-gateway",
        protocol_version: 1,
        daemon_version: "0.1.0",
        instance_id: "instance-1",
      },
    });
    vi.mocked(api.status).mockResolvedValue({
      device_fingerprint: null,
      paired: false,
      core_bridge_reachable: false,
      active_session_count: 0,
      workspace_count: 0,
    });
    vi.mocked(api.listSessions).mockResolvedValue([]);

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText("(not created yet)")).toBeInTheDocument();
    });
  });

  it("shows multiple active sessions", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "ready",
      message: null,
      identity: {
        product_id: "kicad-mcp-gateway",
        protocol_version: 1,
        daemon_version: "0.1.0",
        instance_id: "instance-1",
      },
    });
    vi.mocked(api.status).mockResolvedValue({
      device_fingerprint: "dev_123",
      paired: true,
      core_bridge_reachable: true,
      active_session_count: 3,
      workspace_count: 2,
    });
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_1",
        remote_principal: "user1@remote",
        status: "Active",
        capability_profile: "Design",
        task_scope: "General editing",
        expires_at: "2026-10-01T00:00:00Z",
      },
      {
        session_id: "ses_2",
        remote_principal: "user2@remote",
        status: "Active",
        capability_profile: "View",
        task_scope: "Read-only review",
        expires_at: "2026-10-02T00:00:00Z",
      },
      {
        session_id: "ses_3",
        remote_principal: "ci@build",
        status: "Active",
        capability_profile: "Automation",
        task_scope: "CI build",
        expires_at: "2026-10-03T00:00:00Z",
      },
    ]);

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText(/3 active/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/user1@remote/)).toBeInTheDocument();
    expect(screen.getByText(/user2@remote/)).toBeInTheDocument();
    expect(screen.getByText(/ci@build/)).toBeInTheDocument();
  });

  it("shows failed state with error message from lifecycle", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "failed",
      message: "daemon binary not found at expected path",
      identity: null,
    });
    vi.mocked(api.status).mockRejectedValue("daemon not running");
    vi.mocked(api.listSessions).mockRejectedValue("daemon not running");

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText(/daemon binary not found at expected path/i)).toBeInTheDocument();
    });
    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });

  it("shows both lifecycle error and daemon not reachable when both fail", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "failed",
      message: "startup timeout",
      identity: null,
    });
    vi.mocked(api.status).mockRejectedValue("connection refused");
    vi.mocked(api.listSessions).mockRejectedValue("connection refused");

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText(/startup timeout/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Daemon not reachable: connection refused/i)).toBeInTheDocument();
  });

  it("displays session expiry timestamp", async () => {
    vi.mocked(api.daemonLifecycle).mockResolvedValue({
      state: "ready",
      message: null,
      identity: {
        product_id: "kicad-mcp-gateway",
        protocol_version: 1,
        daemon_version: "0.1.0",
        instance_id: "instance-1",
      },
    });
    vi.mocked(api.status).mockResolvedValue({
      device_fingerprint: "dev_123",
      paired: true,
      core_bridge_reachable: true,
      active_session_count: 1,
      workspace_count: 1,
    });
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_1",
        remote_principal: "user@remote",
        status: "Active",
        capability_profile: "Design",
        task_scope: "General editing",
        expires_at: "2026-10-01T12:34:56Z",
      },
    ]);

    render(<StatusScreen />);

    await waitFor(() => {
      expect(screen.getByText("expires 2026-10-01T12:34:56Z")).toBeInTheDocument();
    });
  });
});