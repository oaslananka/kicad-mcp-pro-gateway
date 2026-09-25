import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import PairingScreen from "../PairingScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    beginPairing: vi.fn(),
  },
}));

describe("PairingScreen", () => {
  it("renders empty state when no pairing in progress", async () => {
    render(<PairingScreen />);

    await waitFor(() => {
      expect(screen.getByText("Device pairing")).toBeInTheDocument();
    });

    expect(screen.getByText("No pairing in progress.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Begin pairing" })).toBeInTheDocument();
  });

  it("shows pairing code and provider when pairing succeeds", async () => {
    vi.mocked(api.beginPairing).mockResolvedValue({
      pairing_code: "ABCD-EFGH-IJKL",
      mock_provider: true,
    });

    render(<PairingScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Begin pairing" })).toBeInTheDocument();
    });

    // Click the begin pairing button
    screen.getByRole("button", { name: "Begin pairing" }).click();

    await waitFor(() => {
      expect(screen.getByText("ABCD-EFGH-IJKL")).toBeInTheDocument();
    });

    expect(screen.getByText("Mock (development)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Begin pairing" })).toBeInTheDocument();
  });

  it("shows error banner when pairing fails", async () => {
    vi.mocked(api.beginPairing).mockRejectedValue("Daemon not reachable: connection refused");

    render(<PairingScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Begin pairing" })).toBeInTheDocument();
    });

    screen.getByRole("button", { name: "Begin pairing" }).click();

    await waitFor(() => {
      expect(screen.getByText(/Daemon not reachable: connection refused/i)).toBeInTheDocument();
    });
  });

  it("disables button while pairing is in progress", async () => {
    let resolvePairing: (value: { pairing_code: string; mock_provider: boolean }) => void;
    const pairingPromise = new Promise<{ pairing_code: string; mock_provider: boolean }>((resolve) => {
      resolvePairing = resolve;
    });
    vi.mocked(api.beginPairing).mockReturnValue(pairingPromise);

    render(<PairingScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Begin pairing" })).toBeInTheDocument();
    });

    screen.getByRole("button", { name: "Begin pairing" }).click();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Starting…" })).toBeDisabled();
    });

    resolvePairing!({ pairing_code: "TEST-CODE", mock_provider: false });

    await waitFor(() => {
      expect(screen.getByText("TEST-CODE")).toBeInTheDocument();
    });
  });

  it("does not overwrite explicit error with subsequent success", async () => {
    vi.mocked(api.beginPairing).mockRejectedValueOnce("Network error");

    render(<PairingScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Begin pairing" })).toBeInTheDocument();
    });

    screen.getByRole("button", { name: "Begin pairing" }).click();

    await waitFor(() => {
      expect(screen.getByText(/Network error/i)).toBeInTheDocument();
    });

    // Now try again with success
    vi.mocked(api.beginPairing).mockResolvedValueOnce({
      pairing_code: "NEW-CODE",
      mock_provider: true,
    });

    // The error should still be visible until user clicks again
    expect(screen.getByText(/Network error/i)).toBeInTheDocument();
  });
});