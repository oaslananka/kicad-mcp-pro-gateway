import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import SessionsScreen from "../SessionsScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    listSessions: vi.fn(),
    listPendingApprovals: vi.fn(),
    pauseSession: vi.fn(),
    revokeSession: vi.fn(),
    approveSession: vi.fn(),
    denySession: vi.fn(),
  },
}));

describe("SessionsScreen", () => {
  it("renders empty state when no sessions or approvals exist", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByText("No sessions yet.")).toBeInTheDocument();
    });
  });

  it("renders active sessions and pending approvals", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_100",
        remote_principal: "agent@cloud",
        status: "Active",
        capability_profile: "Design",
        task_scope: "PCB Routing",
        expires_at: "2026-12-31T23:59:59Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([
      {
        operation_id: "op_200",
        session_id: "ses_100",
        tool_name: "pcb_export_gerber",
        risk: "High",
      },
    ]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByText("agent@cloud")).toBeInTheDocument();
    });

    expect(screen.getByText("PCB Routing")).toBeInTheDocument();
    expect(screen.getByText("pcb_export_gerber")).toBeInTheDocument();
    expect(screen.getByText("High-risk operations awaiting approval")).toBeInTheDocument();
  });

  it("shows the policy-limited effective expiry in the approval dialog", async () => {
    const effectiveExpiry = "2026-09-25T12:07:00Z";
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_300",
        remote_principal: "agent@cloud",
        status: "PendingApproval",
        capability_profile: "Manufacturing",
        task_scope: "Export fabrication files",
        expires_at: effectiveExpiry,
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);

    render(<SessionsScreen />);

    fireEvent.click(await screen.findByRole("button", { name: "Review" }));

    expect(screen.getAllByText("Effective expiry").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(effectiveExpiry).length).toBeGreaterThanOrEqual(2);
  });
});
