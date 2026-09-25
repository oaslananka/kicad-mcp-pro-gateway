import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import ActivityScreen from "../ActivityScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    auditSummary: vi.fn(),
  },
}));

describe("ActivityScreen", () => {
  it("renders activity summary when data is available", async () => {
    vi.mocked(api.auditSummary).mockResolvedValue({
      total_events: 42,
      note: "Audit trail is append-only and tamper-evident",
    });

    render(<ActivityScreen />);

    await waitFor(() => {
      expect(screen.getByText("Activity")).toBeInTheDocument();
    });

    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("Audit trail is append-only and tamper-evident")).toBeInTheDocument();
  });

  it("renders placeholder when no events recorded yet", async () => {
    vi.mocked(api.auditSummary).mockResolvedValue({
      total_events: 0,
      note: "No events recorded yet",
    });

    render(<ActivityScreen />);

    await waitFor(() => {
      expect(screen.getByText("0")).toBeInTheDocument();
    });

    expect(screen.getByText("No events recorded yet")).toBeInTheDocument();
  });

  it("shows error banner when daemon is unreachable", async () => {
    vi.mocked(api.auditSummary).mockRejectedValue("Daemon not reachable: connection refused");

    render(<ActivityScreen />);

    await waitFor(() => {
      expect(screen.getByText(/Daemon not reachable: connection refused/i)).toBeInTheDocument();
    });

    // Should show placeholder for events
    expect(screen.getByText("-")).toBeInTheDocument();
  });

  it("displays note about future per-event browsing", async () => {
    vi.mocked(api.auditSummary).mockResolvedValue({
      total_events: 10,
      note: "Summary available",
    });

    render(<ActivityScreen />);

    await waitFor(() => {
      expect(screen.getByText(/Full per-event browsing/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/audit trail itself is already recorded/i)).toBeInTheDocument();
  });

  it("handles null/undefined data gracefully", async () => {
    vi.mocked(api.auditSummary).mockResolvedValue({
      total_events: null as unknown as number,
      note: null as unknown as string,
    });

    render(<ActivityScreen />);

    await waitFor(() => {
      expect(screen.getByText("-")).toBeInTheDocument();
    });
  });
});