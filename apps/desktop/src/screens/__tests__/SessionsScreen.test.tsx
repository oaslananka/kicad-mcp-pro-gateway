import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
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
    resumeSession: vi.fn(),
    approveOperation: vi.fn(),
    denyOperation: vi.fn(),
  },
}));

describe("SessionsScreen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders empty state when no sessions or approvals exist", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByText(/No sessions yet/i)).toBeInTheDocument();
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
      expect(screen.getByText(/agent@cloud/i)).toBeInTheDocument();
    });

    expect(screen.getByText("PCB Routing")).toBeInTheDocument();
    expect(screen.getByText(/pcb_export_gerber/i)).toBeInTheDocument();
    expect(screen.getByText("High-risk operations awaiting approval")).toBeInTheDocument();
  });

  it("renders session with PendingApproval status and Review button", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_pending",
        remote_principal: "user@remote",
        status: "PendingApproval",
        capability_profile: "Design",
        task_scope: "General editing",
        expires_at: "2026-10-01T00:00:00Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByText("PendingApproval")).toBeInTheDocument();
    });

    expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
  });

  it("renders session with Suspended status and Resume/Revoke buttons", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_suspended",
        remote_principal: "user@remote",
        status: "Suspended",
        capability_profile: "Design",
        task_scope: "General editing",
        expires_at: "2026-10-01T00:00:00Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByText("Suspended")).toBeInTheDocument();
    });

    expect(screen.getByRole("button", { name: "Resume" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
  });

  it("shows error banner when daemon is unreachable", async () => {
    vi.mocked(api.listSessions).mockRejectedValue("Connection refused");
    vi.mocked(api.listPendingApprovals).mockRejectedValue("Connection refused");

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByText(/Daemon not reachable: Connection refused/i)).toBeInTheDocument();
    });

    // When there's an error, the table body is empty (no "No sessions yet" message)
    expect(screen.queryByText(/No sessions yet/i)).not.toBeInTheDocument();
  });

  it("opens session approval dialog when Review is clicked on PendingApproval session", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_100",
        remote_principal: "agent@cloud",
        status: "PendingApproval",
        capability_profile: "Design",
        task_scope: "PCB Routing",
        expires_at: "2026-12-31T23:59:59Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByText("Remote access request")).toBeInTheDocument();
    });

    // Check modal content specifically
    const modal = screen.getByText("Remote access request").closest(".modal") as HTMLElement;
    expect(modal).toBeInTheDocument();
    expect(within(modal).getByText(/agent@cloud/i)).toBeInTheDocument();
    expect(within(modal).getByText("Design")).toBeInTheDocument();
    expect(within(modal).getByText("PCB Routing")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deny" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
  });

  it("opens operation approval dialog when Review is clicked on pending operation", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
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
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByText("High-risk action requires approval")).toBeInTheDocument();
    });

    // Check modal content specifically
    const modal = screen.getByText("High-risk action requires approval").closest(".modal") as HTMLElement;
    expect(modal).toBeInTheDocument();
    expect(within(modal).getByText(/pcb_export_gerber/i)).toBeInTheDocument();
    expect(within(modal).getByText("High")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deny" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Allow Once" })).toBeInTheDocument();
  });

  it("calls approveSession when Approve is clicked in session dialog", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_100",
        remote_principal: "agent@cloud",
        status: "PendingApproval",
        capability_profile: "Design",
        task_scope: "PCB Routing",
        expires_at: "2026-12-31T23:59:59Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);
    vi.mocked(api.approveSession).mockResolvedValue(undefined);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() => {
      expect(api.approveSession).toHaveBeenCalledWith("ses_100");
    });
  });

  it("calls denySession with reason when Deny is clicked in session dialog", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_100",
        remote_principal: "agent@cloud",
        status: "PendingApproval",
        capability_profile: "Design",
        task_scope: "PCB Routing",
        expires_at: "2026-12-31T23:59:59Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);
    vi.mocked(api.denySession).mockResolvedValue(undefined);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Deny" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Deny" }));

    await waitFor(() => {
      expect(api.denySession).toHaveBeenCalledWith("ses_100", "denied by user");
    });
  });

  it("calls approveOperation when Allow Once is clicked in operation dialog", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([
      {
        operation_id: "op_200",
        session_id: "ses_100",
        tool_name: "pcb_export_gerber",
        risk: "High",
      },
    ]);
    vi.mocked(api.approveOperation).mockResolvedValue(undefined);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Allow Once" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Allow Once" }));

    await waitFor(() => {
      expect(api.approveOperation).toHaveBeenCalledWith("op_200");
    });
  });

  it("calls denyOperation with reason when Deny is clicked in operation dialog", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([
      {
        operation_id: "op_200",
        session_id: "ses_100",
        tool_name: "pcb_export_gerber",
        risk: "High",
      },
    ]);
    vi.mocked(api.denyOperation).mockResolvedValue(undefined);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Deny" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Deny" }));

    await waitFor(() => {
      expect(api.denyOperation).toHaveBeenCalledWith("op_200", "denied by user");
    });
  });

  it("calls pauseSession when Pause is clicked on Active session", async () => {
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
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);
    vi.mocked(api.pauseSession).mockResolvedValue(undefined);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Pause" }));

    await waitFor(() => {
      expect(api.pauseSession).toHaveBeenCalledWith("ses_100");
    });
  });

  it("calls revokeSession when Revoke is clicked on Active session", async () => {
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
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);
    vi.mocked(api.revokeSession).mockResolvedValue(undefined);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() => {
      expect(api.revokeSession).toHaveBeenCalledWith("ses_100");
    });
  });

  it("calls resumeSession when Resume is clicked on Suspended session", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_100",
        remote_principal: "agent@cloud",
        status: "Suspended",
        capability_profile: "Design",
        task_scope: "PCB Routing",
        expires_at: "2026-12-31T23:59:59Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);
    vi.mocked(api.resumeSession).mockResolvedValue(undefined);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Resume" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Resume" }));

    await waitFor(() => {
      expect(api.resumeSession).toHaveBeenCalledWith("ses_100");
    });
  });

  it("shows action error when session action fails", async () => {
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
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);
    vi.mocked(api.pauseSession).mockRejectedValue("Session not found");

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Pause" }));

    await waitFor(() => {
      expect(screen.getByText("Session not found")).toBeInTheDocument();
    });
  });

  it("shows action error when operation approval fails", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([
      {
        operation_id: "op_200",
        session_id: "ses_100",
        tool_name: "pcb_export_gerber",
        risk: "High",
      },
    ]);
    vi.mocked(api.approveOperation).mockRejectedValue("Operation expired");

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Allow Once" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Allow Once" }));

    await waitFor(() => {
      expect(screen.getByText("Operation expired")).toBeInTheDocument();
    });
  });

  it("closes session dialog when clicking backdrop", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([
      {
        session_id: "ses_100",
        remote_principal: "agent@cloud",
        status: "PendingApproval",
        capability_profile: "Design",
        task_scope: "PCB Routing",
        expires_at: "2026-12-31T23:59:59Z",
      },
    ]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByText("Remote access request")).toBeInTheDocument();
    });

    // Click on the backdrop (not the modal content)
    const backdrop = screen.getByTestId("session-dialog-backdrop");
    fireEvent.click(backdrop);

    await waitFor(() => {
      expect(screen.queryByText("Remote access request")).not.toBeInTheDocument();
    });
  });

  it("closes operation dialog when clicking backdrop", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
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
      expect(screen.getByRole("button", { name: "Review" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));

    await waitFor(() => {
      expect(screen.getByText("High-risk action requires approval")).toBeInTheDocument();
    });

    // Click on the backdrop (not the modal content)
    const backdrop = screen.getByTestId("operation-dialog-backdrop");
    fireEvent.click(backdrop);

    await waitFor(() => {
      expect(screen.queryByText("High-risk action requires approval")).not.toBeInTheDocument();
    });
  });

  it("displays risk badge correctly for Critical risk", async () => {
    vi.mocked(api.listSessions).mockResolvedValue([]);
    vi.mocked(api.listPendingApprovals).mockResolvedValue([
      {
        operation_id: "op_critical",
        session_id: "ses_100",
        tool_name: "dangerous_tool",
        risk: "Critical",
      },
    ]);

    render(<SessionsScreen />);

    await waitFor(() => {
      expect(screen.getByText("Critical")).toBeInTheDocument();
    });

    const riskBadge = screen.getByText("Critical").closest("span");
    expect(riskBadge).toHaveClass("risk-high");
  });
});