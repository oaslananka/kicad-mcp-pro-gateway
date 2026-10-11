import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SetupScreen from "../SetupScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    pairingStatus: vi.fn(),
    submitCloudPairing: vi.fn(),
    listWorkspaces: vi.fn(),
    authorizeWorkspace: vi.fn(),
    selectProjectFolder: vi.fn(),
  },
}));

describe("SetupScreen — actual Gateway IPC three stages", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.pairingStatus).mockResolvedValue({ paired: false, device_fingerprint: null });
    vi.mocked(api.listWorkspaces).mockResolvedValue([]);
  });

  it("shows real pairing rather than the development mock", async () => {
    render(<SetupScreen />);
    expect(screen.getByRole("heading", { name: "Üç adımda hazırla" })).toBeInTheDocument();
    expect(screen.getByText(/terminal komutu gerekmez/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Cihaz kanıtını gönder/ })).toBeDisabled();
    expect(screen.queryByText(/Mock \\(development\\)/)).not.toBeInTheDocument();
    expect(vi.mocked(api.submitCloudPairing)).not.toHaveBeenCalled();
  });

  it("submits a valid invitation via the daemon and awaits owner approval", async () => {
    vi.mocked(api.submitCloudPairing).mockResolvedValue(undefined);
    render(<SetupScreen />);
    const code = "A".repeat(26);
    fireEvent.change(screen.getByLabelText("Tek kullanımlık eşleştirme kodu"),
      { target: { value: code } });
    fireEvent.click(screen.getByRole("button", { name: /Cihaz kanıtını gönder/ }));
    await waitFor(() => expect(api.submitCloudPairing).toHaveBeenCalledWith(code));
    await waitFor(() => expect(screen.getByText("Web onayı bekleniyor")).toBeInTheDocument());
    expect(screen.getByText(/Web panelinde parmak izini/)).toBeInTheDocument();
    expect(screen.getByLabelText("Tek kullanımlık eşleştirme kodu")).toHaveValue("");
  });

  it("hides daemon implementation errors and never declares a pairing succeeded", async () => {
    vi.mocked(api.submitCloudPairing).mockRejectedValue("LOCAL OS KEYSTORE PRIVATE VALUE");
    render(<SetupScreen />);
    fireEvent.change(screen.getByLabelText("Tek kullanımlık eşleştirme kodu"),
      { target: { value: "A".repeat(26) } });
    fireEvent.click(screen.getByRole("button", { name: /Cihaz kanıtını gönder/ }));
    await waitFor(() => expect(screen.getByText(/Eşleştirme isteği gönderilemedi/)).toBeInTheDocument());
    expect(screen.queryByText(/LOCAL OS KEYSTORE/)).not.toBeInTheDocument();
    expect(screen.getByText("Eşleştirme bekleniyor")).toBeInTheDocument();
  });

  it("identifies the genuinely unavailable ChatGPT OAuth step", async () => {
    render(<SetupScreen />);
    fireEvent.click(screen.getByRole("button", { name: /Sonraki aşama/ }));
    expect(screen.getByRole("heading", { name: "ChatGPT bağlantısı" })).toBeInTheDocument();
    expect(screen.getByText("Henüz kullanılamıyor")).toBeInTheDocument();
    expect(screen.getByText(/bağlantı başarısız olur/)).toBeInTheDocument();
    expect(screen.getByText("https://kicad-mcp-pro.oaslananka.dev/mcp")).toBeInTheDocument();
    expect(vi.mocked(api.submitCloudPairing)).not.toHaveBeenCalled();
  });

  it("selects a native directory then submits only to the local workspace policy IPC", async () => {
    vi.mocked(api.selectProjectFolder).mockResolvedValue("/home/user/KiCad/project");
    vi.mocked(api.authorizeWorkspace).mockResolvedValue({
      workspace_id: "ws-1", canonical_root: "/home/user/KiCad/project",
      display_name: "Project", enabled: true,
    });
    render(<SetupScreen />);
    fireEvent.click(screen.getByRole("button", { name: /Sonraki aşama/ }));
    fireEvent.click(screen.getByRole("button", { name: /Sonraki aşama/ }));
    fireEvent.click(screen.getByRole("button", { name: "Klasör seç…" }));
    await waitFor(() => expect(api.selectProjectFolder).toHaveBeenCalledOnce());
    await waitFor(() => expect(screen.getByLabelText("Proje klasörü")).toHaveValue("/home/user/KiCad/project"));
    fireEvent.click(screen.getByRole("button", { name: "Projeyi yerel Gateway'e ekle" }));
    await waitFor(() => expect(api.authorizeWorkspace).toHaveBeenCalledWith(
      "/home/user/KiCad/project", "/home/user/KiCad/project",
    ));
    expect(screen.getByText(/ChatGPT araç izni verilmedi/)).toBeInTheDocument();
  });
});
