import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from datetime import datetime

APP_TITLE = "Easy Cook"
APP_VERSION = "1.2.1"

# Default profile directory (same folder as this script)
SCRIPT_DIR = Path(sys.argv[0]).resolve().parent
DEFAULT_PROFILE_NAME = "Default"

TARGET_PLATFORMS = [
    "WindowsNoEditor",
    "Windows",
    "LinuxNoEditor",
    "Linux",
    "Android",
    "IOS",
    "MacNoEditor",
    "Mac",
]

# Regex to extract a package path from Unreal object reference or raw path
OBJREF_RE = re.compile(
    r'''(?ix)
    ^
    (?:
        [A-Za-z_][A-Za-z0-9_]*     # Optional class prefix e.g. DataTable, StaticMesh, Blueprint
        \s*'\s*                    # Quote after class
    )?
    (?P<pkg>/Game(?:/[^.'"]+)+)    # /Game/... package path
    (?:
        \\. [^'\"]+                  # .ObjectName
        \s*'                       # trailing quote
    )?
    $
    '''
)

# ----------------- helpers -----------------

def normalize_asset_path(text: str) -> str:
    """Convert various inputs/obj refs to /Game/... package path."""
    text = text.strip()
    m = OBJREF_RE.match(text)
    if m:
        return m.group("pkg")
    # Try to salvage common inputs like Content/... or Props/Chair.uasset
    if text.lower().startswith("content\\") or text.lower().startswith("content/"):
        # Turn Content/Foo/Bar.uasset -> /Game/Foo/Bar
        p = Path(text.replace("\\", "/"))
        parts = list(p.parts)
        if parts and parts[0].lower() == "content":
            parts = parts[1:]
        if parts:
            parts[-1] = Path(parts[-1]).stem
        return "/Game/" + "/".join(parts)
    # If it's already /Game but includes extension, drop it
    if text.startswith("/Game/"):
        return "/".join([*text.split("/")[:-1], Path(text).stem])
    return text


def to_package_from_filesystem(path: Path, content_root: Path | None) -> str | None:
    """
    Convert a filesystem path to a /Game/... package path.
    - If content_root is provided and path is under it, use that.
    - Otherwise, try to find a 'Content' segment in the path.
    Returns None if conversion fails.
    """
    path = path.resolve()
    if content_root and content_root in path.parents:
        rel = path.relative_to(content_root)
        return "/Game/" + "/".join(rel.with_suffix("").parts)
    # Fallback: search for "Content" in the path
    parts = [p for p in path.parts]
    if "Content" in parts:
        idx = parts.index("Content")
        rel = Path(*parts[idx+1:])
        return "/Game/" + "/".join(rel.with_suffix("").parts)
    return None


def scan_folder_to_packages(folder: Path, content_root: Path | None) -> list[str]:
    pkgs = []
    for p in folder.rglob("*.uasset"):
        pkg = to_package_from_filesystem(p, content_root)
        if pkg:
            pkgs.append(pkg)
    return pkgs


def folder_to_game_path(folder: Path, content_root: Path | None) -> str | None:
    """Convert a folder on disk to a virtual /Game/... folder path for display.
    Returns None if it cannot be mapped (e.g., not under a Content directory).
    """
    try:
        folder = folder.resolve()
    except Exception:
        folder = Path(folder)

    # If we know the project's Content root, prefer that
    if content_root:
        try:
            content_root = content_root.resolve()
        except Exception:
            pass
        if folder == content_root:
            return "/Game"
        if content_root in folder.parents:
            rel = folder.relative_to(content_root)
            if not rel.parts:
                return "/Game"
            return "/Game/" + "/".join(rel.parts)

    # Fallback: search for a "Content" segment in the path
    parts = list(folder.parts)
    if "Content" in parts:
        idx = parts.index("Content")
        after = parts[idx + 1 :]
        if not after:
            return "/Game"
        return "/Game/" + "/".join(after)

    return None


# ----------------- UI -----------------

class CollapsibleFrame(ttk.Frame):
    def __init__(self, master, text="", *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.columnconfigure(0, weight=1)
        self._expanded = tk.BooleanVar(value=False)
        self._header = ttk.Frame(self)
        self._header.grid(row=0, column=0, sticky="ew")
        self._btn = ttk.Checkbutton(self._header, text=text, variable=self._expanded, style="Toolbutton", command=self._toggle)
        self._btn.pack(side="left", padx=2, pady=2)
        self._body = ttk.Frame(self)
        self._body.grid(row=1, column=0, sticky="nsew")
        self._body.grid_remove()

    def _toggle(self):
        if self._expanded.get():
            self._body.grid()
        else:
            self._body.grid_remove()

    @property
    def body(self):
        return self._body


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("980x720")
        self.minsize(900, 620)

        # State: backing store for list items so we can track folders distinctly
        # items: list[ {"type":"asset","value":"/Game/..."} | {"type":"folder","value":"C:/.../SomeFolder"} ]
        self.items: list[dict] = []
        self.proc = None
        self.proc_thread = None
        self.log_queue = queue.Queue()

        # Top: Paths
        paths = ttk.LabelFrame(self, text="Paths")
        paths.pack(fill="x", padx=10, pady=(10, 6))

        self.ue_path_var = tk.StringVar()
        ttk.Label(paths, text="UE4Editor.exe:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(paths, textvariable=self.ue_path_var).grid(row=0, column=1, sticky="ew", padx=(0,8), pady=6)
        ttk.Button(paths, text="Browse…", command=self.pick_ue).grid(row=0, column=2, sticky="e", padx=8, pady=6)

        self.uproject_var = tk.StringVar()
        ttk.Label(paths, text=".uproject:").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(paths, textvariable=self.uproject_var).grid(row=1, column=1, sticky="ew", padx=(0,8), pady=6)
        ttk.Button(paths, text="Browse…", command=self.pick_project).grid(row=1, column=2, sticky="e", padx=8, pady=6)

        paths.columnconfigure(1, weight=1)

        # Middle: Assets & Options
        middle = ttk.Frame(self)
        middle.pack(fill="both", expand=True, padx=10, pady=6)
        middle.columnconfigure(0, weight=3)
        middle.columnconfigure(1, weight=2)

        # Assets panel
        assets_frame = ttk.LabelFrame(middle, text="Cook List")
        assets_frame.grid(row=0, column=0, sticky="nsew", padx=(0,6))
        assets_frame.columnconfigure(0, weight=1)

        entry_row = ttk.Frame(assets_frame)
        entry_row.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
        self.asset_entry = ttk.Entry(entry_row)
        self.asset_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(entry_row, text="Add Asset", command=self.add_asset).pack(side="left", padx=4)
        ttk.Button(entry_row, text="Paste & Add", command=self.paste_add).pack(side="left", padx=4)
        ttk.Button(entry_row, text="Add Folder…", command=self.add_folder).pack(side="left", padx=4)

        self.listbox = tk.Listbox(assets_frame, selectmode=tk.EXTENDED)
        self.listbox.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0,6))
        assets_frame.rowconfigure(1, weight=1)

        btn_row = ttk.Frame(assets_frame)
        btn_row.grid(row=2, column=0, sticky="ew", padx=6, pady=(0,6))
        ttk.Button(btn_row, text="Remove Selected", command=self.remove_selected).pack(side="left")
        ttk.Button(btn_row, text="Clear", command=self.clear_items).pack(side="left", padx=6)

        # Options panel
        options = ttk.LabelFrame(middle, text="Options")
        options.grid(row=0, column=1, sticky="nsew")

        ttk.Label(options, text="Target Platform:").grid(row=0, column=0, sticky="w", padx=8, pady=(8,4))
        self.platform_var = tk.StringVar(value="WindowsNoEditor")
        ttk.Combobox(options, textvariable=self.platform_var, values=TARGET_PLATFORMS, state="readonly").grid(row=0, column=1, sticky="ew", padx=(0,8), pady=(8,4))

        ttk.Label(options, text="Cultures (optional):").grid(row=1, column=0, sticky="w", padx=8, pady=4)
        self.cultures_var = tk.StringVar()
        ttk.Entry(options, textvariable=self.cultures_var).grid(row=1, column=1, sticky="ew", padx=(0,8), pady=4)
        ttk.Label(options, text="e.g. en,fr,de").grid(row=1, column=2, sticky="w", padx=4)

        self.adv = CollapsibleFrame(options, text="Advanced Settings ▾")
        self.adv.grid(row=2, column=0, columnspan=3, sticky="ew", padx=4, pady=(6,8))
        adv = self.adv.body
        self.opt_iterate = tk.BooleanVar(value=False)
        self.opt_unversioned = tk.BooleanVar(value=False)
        self.opt_compressed = tk.BooleanVar(value=False)
        self.opt_nop4 = tk.BooleanVar(value=True)
        self.opt_unattended = tk.BooleanVar(value=True)
        self.opt_stdout = tk.BooleanVar(value=True)
        self.opt_additional = tk.StringVar(value="")

        ttk.Checkbutton(adv, text="Iterative (-iterate)", variable=self.opt_iterate).grid(row=0, column=0, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(adv, text="Unversioned (-unversioned)", variable=self.opt_unversioned).grid(row=1, column=0, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(adv, text="Compressed (-compressed)", variable=self.opt_compressed).grid(row=2, column=0, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(adv, text="No Perforce (-nop4)", variable=self.opt_nop4).grid(row=0, column=1, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(adv, text="Unattended (-unattended)", variable=self.opt_unattended).grid(row=1, column=1, sticky="w", padx=8, pady=4)
        ttk.Checkbutton(adv, text="Log to console (-stdout)", variable=self.opt_stdout).grid(row=2, column=1, sticky="w", padx=8, pady=4)

        ttk.Label(adv, text="Extra flags:").grid(row=3, column=0, sticky="w", padx=8, pady=(8,4))
        ttk.Entry(adv, textvariable=self.opt_additional).grid(row=3, column=1, columnspan=2, sticky="ew", padx=(0,8), pady=(8,4))

        for i in range(3):
            adv.columnconfigure(i, weight=1)
        for i in range(3):
            options.columnconfigure(i, weight=1)

        # Profile Management Section
        profile_frame = ttk.LabelFrame(self, text="Profile Management")
        profile_frame.pack(fill="x", padx=10, pady=(6,0))
        
        profile_top = ttk.Frame(profile_frame)
        profile_top.pack(fill="x", padx=8, pady=8)
        
        # Profile name entry and save
        ttk.Label(profile_top, text="Profile Name:").pack(side="left")
        self.profile_name_var = tk.StringVar(value=DEFAULT_PROFILE_NAME)
        ttk.Entry(profile_top, textvariable=self.profile_name_var, width=20).pack(side="left", padx=(8,12))
        ttk.Button(profile_top, text="Save Profile", command=self.save_profile).pack(side="left", padx=(0,16))
        
        # Profile selection and load
        ttk.Label(profile_top, text="Load Profile:").pack(side="left")
        self.profile_selector = ttk.Combobox(profile_top, state="readonly", width=25)
        self.profile_selector.pack(side="left", padx=(8,8))
        ttk.Button(profile_top, text="Load", command=self.load_selected_profile).pack(side="left", padx=(0,8))
        ttk.Button(profile_top, text="Refresh", command=self.refresh_profiles).pack(side="left")

        # Cooking Controls Section
        controls = ttk.LabelFrame(self, text="Cooking Operations")
        controls.pack(fill="x", padx=10, pady=(8,0))
        
        controls_inner = ttk.Frame(controls)
        controls_inner.pack(fill="x", padx=8, pady=8)
        
        # Run controls
        self.run_btn = ttk.Button(controls_inner, text="Run Cook", command=self.run_cook)
        self.run_btn.pack(side="left", padx=(0,12))
        self.cancel_btn = ttk.Button(controls_inner, text="Cancel", command=self.cancel_cook, state="disabled")
        self.cancel_btn.pack(side="left", padx=(0,12))
        self.preview_btn = ttk.Button(controls_inner, text="Copy Command", command=self.copy_command)
        self.preview_btn.pack(side="left")

        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.log = ScrolledText(log_frame, height=12, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True, padx=6, pady=6)

        # Set icon (compatible with PyInstaller bundle)
        def resource_path(relative_path):
            try:
                base_path = sys._MEIPASS
            except AttributeError:
                base_path = os.path.abspath(".")
            return os.path.join(base_path, relative_path)

        try:
            if os.name == "nt":  # Windows
                self.iconbitmap(resource_path("icon.ico"))
            else:  # Linux / macOS
                self.iconphoto(True, tk.PhotoImage(file=resource_path("icon.png")))
        except Exception as e:
            print(f"Failed to set icon: {e}")

        self.refresh_profiles()
        self.after(80, self._poll_log_queue)

    # ---------- UI helpers ----------
    def pick_ue(self):
        path = filedialog.askopenfilename(
            title="Select UE4Editor.exe",
            filetypes=[("UE4Editor", "UE4Editor.exe"), ("Executables", "*.exe"), ("All files", "*.*")],
        )
        if path:
            self.ue_path_var.set(path)

    def pick_project(self):
        path = filedialog.askopenfilename(
            title="Select .uproject",
            filetypes=[("Unreal Project", "*.uproject"), ("All files", "*.*")],
        )
        if path:
            self.uproject_var.set(path)

    def _add_asset_internal(self, pkg: str) -> bool:
        pkg = normalize_asset_path(pkg)
        if not pkg.startswith("/Game/"):
            return False
        # dedupe assets
        if any(it["type"] == "asset" and it["value"].lower() == pkg.lower() for it in self.items):
            return False
        self.items.append({"type": "asset", "value": pkg})
        self._refresh_listbox()
        return True

    def add_asset(self):
        raw = self.asset_entry.get().strip()
        if not raw:
            return
        if raw.startswith("[Folder]"):
            messagebox.showinfo("Hint", "Use 'Add Folder…' to add a folder.")
            return
        ok = self._add_asset_internal(raw)
        if not ok:
            if raw.startswith("/Game/"):
                messagebox.showinfo("Duplicate/Invalid", f"Already in list or invalid: {raw}")
            else:
                if messagebox.askyesno("Unusual Path", f"'{raw}' doesn't look like a /Game/ package path.\nAdd anyway as plain text?"):
                    self.items.append({"type": "asset", "value": raw})
                    self._refresh_listbox()
        self.asset_entry.delete(0, tk.END)

    def add_folder(self):
        folder = filedialog.askdirectory(title="Choose folder containing assets")
        if not folder:
            return
        folder_path = str(Path(folder).resolve())
        # dedupe folder entries
        if any(it["type"] == "folder" and it["value"].lower() == folder_path.lower() for it in self.items):
            self._log("Folder already in list.")
            return
        self.items.append({"type": "folder", "value": folder_path})
        self._refresh_listbox()
        display = folder_to_game_path(Path(folder_path), self._infer_content_root())
        self._log(f"Added folder: {display if display else folder_path}")

    def paste_add(self):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return
        tokens = re.findall(r"[^\s]+", text)
        added = 0
        for t in tokens:
            if self._add_asset_internal(t):
                added += 1
        self._log(f"Added {added} asset(s) from clipboard.")

    def remove_selected(self):
        sel = list(self.listbox.curselection())
        sel.sort(reverse=True)
        for i in sel:
            del self.items[i]
        self._refresh_listbox()

    def clear_items(self):
        self.items.clear()
        self._refresh_listbox()

    def _refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        content_root = self._infer_content_root()
        for it in self.items:
            if it["type"] == "asset":
                self.listbox.insert(tk.END, f"🎯 {it['value']}")
            else:
                # Show folder as /Game/... if we can map it, otherwise keep full path
                fp = Path(it["value"]) if it.get("value") else None
                display = None
                if fp:
                    display = folder_to_game_path(fp, content_root)
                self.listbox.insert(tk.END, f"📁 {display if display else it['value']}")

    # ---------- Profiles (multiple) ----------
    def _profile_path(self, name: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip()) or DEFAULT_PROFILE_NAME
        return SCRIPT_DIR / f"EasyCook_{safe}.json"

    def refresh_profiles(self):
        files = sorted(SCRIPT_DIR.glob("EasyCook_*.json"))
        names = [f.stem.replace("EasyCook_", "") for f in files]
        if DEFAULT_PROFILE_NAME not in names:
            names.insert(0, DEFAULT_PROFILE_NAME)
        self.profile_selector["values"] = names
        if not self.profile_selector.get() and names:
            self.profile_selector.set(names[0])

    def save_profile(self):
        name = self.profile_name_var.get().strip() or DEFAULT_PROFILE_NAME
        path = self._profile_path(name)
        data = {
            "ue4editor": self.ue_path_var.get(),
            "uproject": self.uproject_var.get(),
            "platform": self.platform_var.get(),
            "cultures": self.cultures_var.get(),
            "items": self.items,
            "options": {
                "iterate": self.opt_iterate.get(),
                "unversioned": self.opt_unversioned.get(),
                "compressed": self.opt_compressed.get(),
                "nop4": self.opt_nop4.get(),
                "unattended": self.opt_unattended.get(),
                "stdout": self.opt_stdout.get(),
                "extra": self.opt_additional.get(),
            },
            "version": APP_VERSION,
        }
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self._log(f"Saved profile to {path}")
            messagebox.showinfo("Saved", f"Saved profile to:\n{path}")
            self.refresh_profiles()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profile:\n{e}")

    def load_selected_profile(self):
        name = self.profile_selector.get().strip()
        if not name:
            messagebox.showinfo("Select Profile", "Pick a profile from the dropdown.")
            return
        path = self._profile_path(name)
        if not path.exists():
            messagebox.showinfo("Not Found", f"No profile at:\n{path}")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load:\n{e}")
            return
        self.profile_name_var.set(name)
        self.ue_path_var.set(data.get("ue4editor", ""))
        self.uproject_var.set(data.get("uproject", ""))
        self.platform_var.set(data.get("platform", "WindowsNoEditor"))
        self.cultures_var.set(data.get("cultures", ""))
        self.items = data.get("items") or [
            {"type": "asset", "value": a} for a in data.get("assets", [])
        ]
        self._refresh_listbox()
        opts = data.get("options", {})
        self.opt_iterate.set(opts.get("iterate", False))
        self.opt_unversioned.set(opts.get("unversioned", False))
        self.opt_compressed.set(opts.get("compressed", False))
        self.opt_nop4.set(opts.get("nop4", True))
        self.opt_unattended.set(opts.get("unattended", True))
        self.opt_stdout.set(opts.get("stdout", True))
        self.opt_additional.set(opts.get("extra", ""))
        self._log(f"Loaded profile from {path}")

    # ---------- Asset resolution (folders -> assets) ----------
    def _infer_content_root(self) -> Path | None:
        proj = self.uproject_var.get().strip().strip('"')
        if proj and Path(proj).is_file():
            pr = Path(proj).resolve().parent  # project root
            c = pr / "Content"
            if c.exists():
                return c.resolve()
        return None

    def _resolve_items_to_assets(self, show_loading: bool = True) -> list[str]:
        # Gather explicit assets
        assets_set = set(
            it["value"].strip() for it in self.items if it["type"] == "asset"
        )
        # Expand folders
        folders = [Path(it["value"]) for it in self.items if it["type"] == "folder"]
        if not folders:
            return sorted(assets_set)

        content_root = self._infer_content_root()

        loading_win = None
        stop_flag = {"stop": False}

        def open_loading():
            nonlocal loading_win
            loading_win = tk.Toplevel(self)
            loading_win.title("Scanning folders…")
            loading_win.geometry("360x120")
            loading_win.transient(self)
            loading_win.grab_set()
            ttk.Label(loading_win, text="Expanding folder(s) into assets…").pack(pady=(16,8))
            pb = ttk.Progressbar(loading_win, mode="indeterminate")
            pb.pack(fill="x", padx=16)
            pb.start(10)
            ttk.Label(loading_win, text="This may take a moment for large folders.").pack(pady=8)

        def close_loading():
            if loading_win and loading_win.winfo_exists():
                loading_win.grab_release()
                loading_win.destroy()

        def worker():
            try:
                for f in folders:
                    for pkg in scan_folder_to_packages(f, content_root):
                        assets_set.add(pkg)
            finally:
                stop_flag["stop"] = True

        if show_loading:
            open_loading()
        t = threading.Thread(target=worker, daemon=True)
        t.start()

        # pump UI until done
        while not stop_flag["stop"]:
            if loading_win:
                loading_win.update()
            self.update()
            time.sleep(0.03)
        close_loading()
        return sorted(assets_set)

    # ---------- Build & actions ----------
    def _build_args(self, resolved_assets: list[str]) -> list[str]:
        ue = self.ue_path_var.get().strip().strip('"')
        project = self.uproject_var.get().strip().strip('"')
        platform = self.platform_var.get().strip()
        cultures = [c.strip() for c in self.cultures_var.get().split(",") if c.strip()]

        if not ue or not os.path.isfile(ue):
            raise ValueError("Please select a valid UE4Editor.exe path.")
        if not project or not os.path.isfile(project):
            raise ValueError("Please select a valid .uproject file.")
        if not resolved_assets:
            raise ValueError("Your cook list is empty.")

        args = [ue, project, "-run=cook", f"-targetplatform={platform}", "-cooksinglepackage"]
        for a in resolved_assets:
            args.append(f"-map={a}")
        if cultures:
            args.append(f"-cookcultures={';'.join(cultures)}")
        if self.opt_iterate.get():
            args.append("-iterate")
        if self.opt_unversioned.get():
            args.append("-unversioned")
        if self.opt_compressed.get():
            args.append("-compressed")
        if self.opt_nop4.get():
            args.append("-nop4")
        if self.opt_unattended.get():
            args.append("-unattended")
        if self.opt_stdout.get():
            args.append("-stdout")
        extra = self.opt_additional.get().strip()
        if extra:
            extra_parts = re.findall(r"""[^\s"']+|"[^"]*"|'[^']*'""", extra)
            args.extend(extra_parts)
        return args

    def copy_command(self):
        try:
            resolved = self._resolve_items_to_assets(show_loading=True)
            args = self._build_args(resolved)
        except Exception as e:
            messagebox.showerror("Invalid Settings", str(e))
            return
        def q(a):
            if re.search(r'[ \t&^|()<>"]', a):
                return '"' + a.replace('"', '\\"') + '"'
            return a
        cmdline = " ".join(q(a) for a in args)
        self.clipboard_clear()
        self.clipboard_append(cmdline)
        self._log("Command copied to clipboard.")

    def run_cook(self):
        if self.proc is not None:
            return
        try:
            resolved = self._resolve_items_to_assets(show_loading=True)
            args = self._build_args(resolved)
        except Exception as e:
            messagebox.showerror("Invalid Settings", str(e))
            return

        self._log("Starting cook...\n" + " ".join(args))
        self.run_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")

        def worker():
            try:
                self.proc = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    universal_newlines=True,
                )
                assert self.proc.stdout is not None
                for line in self.proc.stdout:
                    self.log_queue.put(line.rstrip("\n"))
                self.proc.wait()
                self.log_queue.put(f"\nProcess exited with code {self.proc.returncode}")
            except FileNotFoundError as e:
                self.log_queue.put(f"Error: {e}")
            except Exception as e:
                self.log_queue.put(f"Unexpected error: {e}")
            finally:
                self.proc = None
                self.log_queue.put("__DONE__")

        self.proc_thread = threading.Thread(target=worker, daemon=True)
        self.proc_thread.start()

    def cancel_cook(self):
        if self.proc is None:
            return
        self._log("Cancelling...")
        try:
            self.proc.terminate()
        except Exception as e:
            self._log(f"Terminate failed: {e}")

    def _poll_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                if msg == "__DONE__":
                    self.run_btn.config(state="normal")
                    self.cancel_btn.config(state="disabled")
                else:
                    self._log(msg)
        except queue.Empty:
            pass
        self.after(80, self._poll_log_queue)

    def _log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")


if __name__ == "__main__":
    app = App()
    app.mainloop()
