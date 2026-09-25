import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import WorkspacesScreen from "../WorkspacesScreen";
import { api } from "../../api/client";

vi.mock("../../api/client", () => ({
  api: {
    listWorkspaces: vi.fn(),
    authorizeWorkspace: vi.fn(),
    removeWorkspace: vi.fn(),
  },
}));

describe("WorkspacesScreen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders empty state when no workspaces exist", async () => {
    vi.mocked(api.listWorkspaces).mockResolvedValue([]);

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText("Workspaces")).toBeInTheDocument();
    });

    expect(screen.getByText("No authorized workspaces yet.")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Absolute path to a KiCad project directory")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Authorize" })).toBeInTheDocument();
  });

  it("renders list of authorized workspaces", async () => {
    vi.mocked(api.listWorkspaces).mockResolvedValue([
      {
        workspace_id: "ws_1",
        display_name: "My Project",
        canonical_root: "/home/user/projects/kicad-project",
        enabled: true,
      },
      {
        workspace_id: "ws_2",
        display_name: "Another Project",
        canonical_root: "/home/user/projects/another",
        enabled: false,
      },
    ]);

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText("My Project")).toBeInTheDocument();
    });

    expect(screen.getByText("/home/user/projects/kicad-project")).toBeInTheDocument();
    expect(screen.getByText("Yes")).toBeInTheDocument();
    expect(screen.getByText("Another Project")).toBeInTheDocument();
    expect(screen.getByText("No")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Remove" })).toHaveLength(2);
  });

  it("shows error banner when daemon is unreachable", async () => {
    vi.mocked(api.listWorkspaces).mockRejectedValue("Daemon not reachable: connection refused");

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText(/Daemon not reachable: connection refused/i)).toBeInTheDocument();
    });
  });

  it("allows adding a new workspace", async () => {
    let callCount = 0;
    vi.mocked(api.listWorkspaces).mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        return Promise.resolve([]);
      }
      // After refresh, return the new workspace
      return Promise.resolve([
        {
          workspace_id: "ws_new",
          display_name: "New Project",
          canonical_root: "/home/user/new-project",
          enabled: true,
        },
      ]);
    });
    vi.mocked(api.authorizeWorkspace).mockResolvedValue({
      workspace_id: "ws_new",
      display_name: "New Project",
      canonical_root: "/home/user/new-project",
      enabled: true,
    });

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText("No authorized workspaces yet.")).toBeInTheDocument();
    });

    // Fill in the path
    const pathInput = screen.getByPlaceholderText("Absolute path to a KiCad project directory");
    fireEvent.change(pathInput, { target: { value: "/home/user/new-project" } });

    // Click authorize
    screen.getByRole("button", { name: "Authorize" }).click();

    await waitFor(() => {
      expect(api.authorizeWorkspace).toHaveBeenCalledWith("/home/user/new-project", "/home/user/new-project");
    });
  });

  it("allows adding a workspace with custom display name", async () => {
    vi.mocked(api.listWorkspaces).mockResolvedValue([]);
    vi.mocked(api.authorizeWorkspace).mockResolvedValue({
      workspace_id: "ws_new",
      display_name: "Custom Name",
      canonical_root: "/home/user/new-project",
      enabled: true,
    });

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText("No authorized workspaces yet.")).toBeInTheDocument();
    });

    const pathInput = screen.getByPlaceholderText("Absolute path to a KiCad project directory");
    fireEvent.change(pathInput, { target: { value: "/home/user/new-project" } });

    const nameInput = screen.getByPlaceholderText("Display name (optional)");
    fireEvent.change(nameInput, { target: { value: "Custom Name" } });

    screen.getByRole("button", { name: "Authorize" }).click();

    await waitFor(() => {
      expect(api.authorizeWorkspace).toHaveBeenCalledWith("/home/user/new-project", "Custom Name");
    });
  });

  it("disables authorize button when path is empty", async () => {
    vi.mocked(api.listWorkspaces).mockResolvedValue([]);

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Authorize" })).toBeDisabled();
    });
  });

  it("shows action error when authorize fails", async () => {
    vi.mocked(api.listWorkspaces).mockResolvedValue([]);
    vi.mocked(api.authorizeWorkspace).mockRejectedValue("Path already authorized");

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Authorize" })).toBeInTheDocument();
    });

    const pathInput = screen.getByPlaceholderText("Absolute path to a KiCad project directory");
    fireEvent.change(pathInput, { target: { value: "/home/user/existing" } });

    screen.getByRole("button", { name: "Authorize" }).click();

    await waitFor(() => {
      expect(screen.getByText("Path already authorized")).toBeInTheDocument();
    });
  });

  it("allows removing a workspace", async () => {
    let callCount = 0;
    vi.mocked(api.listWorkspaces).mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        return Promise.resolve([
          {
            workspace_id: "ws_1",
            display_name: "To Remove",
            canonical_root: "/home/user/remove-me",
            enabled: true,
          },
        ]);
      }
      // After refresh, return empty list
      return Promise.resolve([]);
    });
    vi.mocked(api.removeWorkspace).mockResolvedValue(undefined);

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText("To Remove")).toBeInTheDocument();
    });

    screen.getByRole("button", { name: "Remove" }).click();

    await waitFor(() => {
      expect(api.removeWorkspace).toHaveBeenCalledWith("ws_1");
    });
  });

  it("shows action error when remove fails", async () => {
    vi.mocked(api.listWorkspaces).mockResolvedValue([
      {
        workspace_id: "ws_1",
        display_name: "Cannot Remove",
        canonical_root: "/home/user/cannot-remove",
        enabled: true,
      },
    ]);
    vi.mocked(api.removeWorkspace).mockRejectedValue("Workspace in use by active session");

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText("Cannot Remove")).toBeInTheDocument();
    });

    screen.getByRole("button", { name: "Remove" }).click();

    await waitFor(() => {
      expect(screen.getByText("Workspace in use by active session")).toBeInTheDocument();
    });
  });

  it("displays security note about workspace authorization", async () => {
    vi.mocked(api.listWorkspaces).mockResolvedValue([]);

    render(<WorkspacesScreen />);

    await waitFor(() => {
      expect(screen.getByText("The daemon only ever accesses paths inside authorized workspace roots.")).toBeInTheDocument();
    });
  });
});