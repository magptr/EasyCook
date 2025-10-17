from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox

from .constants import (
    APP_TITLE,
    APP_VERSION,
    DEFAULT_PROFILE_NAME,
    SCRIPT_DIR,
    TARGET_PLATFORMS,
    THEME_COLOR,
)
from .utils import (
    folder_to_game_path,
    normalize_asset_path,
    resource_path,
    scan_folder_to_packages,
)


class CollapsibleFrame(ctk.CTkFrame):
    def __init__(self, master, text: str = "", *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.columnconfigure(0, weight=1)
        self._expanded = tk.BooleanVar(value=False)
        self._header = ctk.CTkFrame(self)
        self._header.grid(row=0, column=0, sticky="ew")
        self._btn = ctk.CTkSwitch(
            self._header, text=text, variable=self._expanded, command=self._toggle
        )
        self._btn.pack(side="left", padx=5, pady=5)
        self._body = ctk.CTkFrame(self)
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


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("980x720")
        self.minsize(900, 620)

        self._set_appearance_mode(ctk.get_appearance_mode())

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._appearance_mode_var = tk.StringVar(value=ctk.get_appearance_mode())
        self._create_theme_mode_toggle()

        self.items: list[dict] = []
        self.proc = None
        self.proc_thread = None
        self.log_queue = queue.Queue()

        paths = ctk.CTkFrame(self)
        paths.pack(fill="x", padx=10, pady=(10, 6))

        paths_label = ctk.CTkLabel(
            paths, text="Paths", font=ctk.CTkFont(size=14, weight="bold")
        )
        paths_label.grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=(8, 4))

        self.ue_path_var = tk.StringVar()
        ctk.CTkLabel(paths, text="UE4Editor.exe:").grid(
            row=1, column=0, sticky="w", padx=8, pady=6
        )
        ctk.CTkEntry(paths, textvariable=self.ue_path_var).grid(
            row=1, column=1, sticky="ew", padx=(0, 8), pady=6
        )
        ctk.CTkButton(paths, text="Browse…", command=self.pick_ue).grid(
            row=1, column=2, sticky="e", padx=8, pady=6
        )

        self.uproject_var = tk.StringVar()
        ctk.CTkLabel(paths, text=".uproject:").grid(
            row=2, column=0, sticky="w", padx=8, pady=6
        )
        ctk.CTkEntry(paths, textvariable=self.uproject_var).grid(
            row=2, column=1, sticky="ew", padx=(0, 8), pady=6
        )
        ctk.CTkButton(paths, text="Browse…", command=self.pick_project).grid(
            row=2, column=2, sticky="e", padx=8, pady=6
        )

        paths.columnconfigure(1, weight=1)

        middle = ctk.CTkFrame(self)
        middle.pack(fill="both", expand=True, padx=10, pady=6)
        middle.columnconfigure(0, weight=3)
        middle.columnconfigure(1, weight=2)

        assets_frame = ctk.CTkFrame(middle)
        assets_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        assets_frame.columnconfigure(0, weight=1)

        assets_label = ctk.CTkLabel(
            assets_frame, text="Cook List", font=ctk.CTkFont(size=14, weight="bold")
        )
        assets_label.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 0))

        entry_row = ctk.CTkFrame(assets_frame)
        entry_row.grid(row=1, column=0, sticky="ew", padx=6, pady=6)
        self.asset_entry = ctk.CTkEntry(entry_row)
        self.asset_entry.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(entry_row, text="Add Asset", command=self.add_asset).pack(
            side="left", padx=4
        )
        ctk.CTkButton(entry_row, text="Paste & Add", command=self.paste_add).pack(
            side="left", padx=4
        )
        ctk.CTkButton(entry_row, text="Add Folder…", command=self.add_folder).pack(
            side="left", padx=4
        )

        listbox_frame = ctk.CTkFrame(assets_frame)
        listbox_frame.grid(row=2, column=0, sticky="nsew", padx=6, pady=(0, 6))
        listbox_frame.columnconfigure(0, weight=1)
        listbox_frame.rowconfigure(0, weight=1)

        if ctk.get_appearance_mode() == "Dark":
            bg_color = ctk.ThemeManager.theme["CTkFrame"]["fg_color"][1]
            fg_color = "#DCE4EE"
            select_bg = THEME_COLOR["primary"]
        else:
            bg_color = ctk.ThemeManager.theme["CTkFrame"]["fg_color"][0]
            fg_color = "#1A1A1A"
            select_bg = THEME_COLOR["primary"]

        self.listbox = tk.Listbox(
            listbox_frame,
            selectmode=tk.EXTENDED,
            bg=bg_color,
            fg=fg_color,
            selectbackground=select_bg,
            selectforeground="#FFFFFF",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=ctk.ThemeManager.theme["CTkFrame"]["border_color"][1],
            font=("Segoe UI", 11),
        )
        self.listbox.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(listbox_frame, command=self.listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.listbox.config(yscrollcommand=scrollbar.set)

        assets_frame.rowconfigure(2, weight=1)

        btn_row = ctk.CTkFrame(assets_frame)
        btn_row.grid(row=3, column=0, sticky="ew", padx=6, pady=(0, 6))
        ctk.CTkButton(btn_row, text="Remove Selected", command=self.remove_selected).pack(
            side="left"
        )
        ctk.CTkButton(btn_row, text="Clear", command=self.clear_items).pack(
            side="left", padx=6
        )

        options = ctk.CTkFrame(middle)
        options.grid(row=0, column=1, sticky="nsew")

        options_label = ctk.CTkLabel(
            options, text="Options", font=ctk.CTkFont(size=14, weight="bold")
        )
        options_label.grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=(8, 4))

        ctk.CTkLabel(options, text="Target Platform:").grid(
            row=1, column=0, sticky="w", padx=8, pady=(8, 4)
        )
        self.platform_var = tk.StringVar(value="WindowsNoEditor")
        platform_combo = ctk.CTkComboBox(
            options, variable=self.platform_var, values=TARGET_PLATFORMS, state="readonly"
        )
        platform_combo.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(8, 4))

        ctk.CTkLabel(options, text="Cultures (optional):").grid(
            row=2, column=0, sticky="w", padx=8, pady=4
        )
        self.cultures_var = tk.StringVar()
        ctk.CTkEntry(options, textvariable=self.cultures_var).grid(
            row=2, column=1, sticky="ew", padx=(0, 8), pady=4
        )
        ctk.CTkLabel(options, text="e.g. en,fr,de").grid(
            row=2, column=2, sticky="w", padx=4
        )

        self.adv = CollapsibleFrame(options, text="Advanced Settings")
        self.adv.grid(row=3, column=0, columnspan=3, sticky="ew", padx=4, pady=(6, 8))
        adv = self.adv.body
        self.opt_iterate = tk.BooleanVar(value=False)
        self.opt_unversioned = tk.BooleanVar(value=False)
        self.opt_compressed = tk.BooleanVar(value=False)
        self.opt_nop4 = tk.BooleanVar(value=True)
        self.opt_unattended = tk.BooleanVar(value=True)
        self.opt_stdout = tk.BooleanVar(value=True)
        self.opt_additional = tk.StringVar(value="")

        ctk.CTkCheckBox(adv, text="Iterative (-iterate)", variable=self.opt_iterate).grid(
            row=0, column=0, sticky="w", padx=8, pady=4
        )
        ctk.CTkCheckBox(
            adv, text="Unversioned (-unversioned)", variable=self.opt_unversioned
        ).grid(row=1, column=0, sticky="w", padx=8, pady=4)
        ctk.CTkCheckBox(adv, text="Compressed (-compressed)", variable=self.opt_compressed).grid(
            row=2, column=0, sticky="w", padx=8, pady=4
        )
        ctk.CTkCheckBox(adv, text="No Perforce (-nop4)", variable=self.opt_nop4).grid(
            row=0, column=1, sticky="w", padx=8, pady=4
        )
        ctk.CTkCheckBox(adv, text="Unattended (-unattended)", variable=self.opt_unattended).grid(
            row=1, column=1, sticky="w", padx=8, pady=4
        )
        ctk.CTkCheckBox(adv, text="Log to console (-stdout)", variable=self.opt_stdout).grid(
            row=2, column=1, sticky="w", padx=8, pady=4
        )

        ctk.CTkLabel(adv, text="Extra flags:").grid(
            row=3, column=0, sticky="w", padx=8, pady=(8, 4)
        )
        ctk.CTkEntry(adv, textvariable=self.opt_additional).grid(
            row=3, column=1, columnspan=2, sticky="ew", padx=(0, 8), pady=(8, 4)
        )

        for i in range(3):
            adv.columnconfigure(i, weight=1)
        for i in range(3):
            options.columnconfigure(i, weight=1)

        profile_frame = ctk.CTkFrame(self)
        profile_frame.pack(fill="x", padx=10, pady=(6, 0))

        profile_label = ctk.CTkLabel(
            profile_frame, text="Profile Management", font=ctk.CTkFont(size=14, weight="bold")
        )
        profile_label.pack(fill="x", padx=8, pady=(8, 0))

        profile_top = ctk.CTkFrame(profile_frame)
        profile_top.pack(fill="x", padx=8, pady=8)

        ctk.CTkLabel(profile_top, text="Profile Name:").pack(side="left")
        self.profile_name_var = tk.StringVar(value=DEFAULT_PROFILE_NAME)
        ctk.CTkEntry(profile_top, textvariable=self.profile_name_var, width=150).pack(
            side="left", padx=(8, 12)
        )
        ctk.CTkButton(profile_top, text="Save Profile", command=self.save_profile).pack(
            side="left", padx=(0, 16)
        )

        ctk.CTkLabel(profile_top, text="Load Profile:").pack(side="left")
        self.profile_selector = ctk.CTkComboBox(profile_top, width=200)
        self.profile_selector.pack(side="left", padx=(8, 8))
        ctk.CTkButton(profile_top, text="Load", command=self.load_selected_profile).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(profile_top, text="Refresh", command=self.refresh_profiles).pack(
            side="left"
        )

        controls = ctk.CTkFrame(self)
        controls.pack(fill="x", padx=10, pady=(8, 0))

        controls_label = ctk.CTkLabel(
            controls, text="Cooking Operations", font=ctk.CTkFont(size=14, weight="bold")
        )
        controls_label.pack(fill="x", padx=8, pady=(8, 0))

        controls_inner = ctk.CTkFrame(controls)
        controls_inner.pack(fill="x", padx=8, pady=8)

        self.run_btn = ctk.CTkButton(
            controls_inner,
            text="Run Cook",
            command=self.run_cook,
            fg_color=THEME_COLOR["secondary"],
            hover_color=ctk.ThemeManager.theme["CTkButton"]["hover_color"][1],
        )
        self.run_btn.pack(side="left", padx=(0, 12))
        self.cancel_btn = ctk.CTkButton(
            controls_inner,
            text="Cancel",
            command=self.cancel_cook,
            state="disabled",
            fg_color=THEME_COLOR["danger"],
            hover_color="#B71C1C",
        )
        self.cancel_btn.pack(side="left", padx=(0, 12))
        self.preview_btn = ctk.CTkButton(
            controls_inner, text="Copy Command", command=self.copy_command
        )
        self.preview_btn.pack(side="left")

        log_frame = ctk.CTkFrame(self)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        log_label = ctk.CTkLabel(
            log_frame, text="Log", font=ctk.CTkFont(size=14, weight="bold")
        )
        log_label.pack(fill="x", padx=8, pady=(8, 0))

        self.log = ctk.CTkTextbox(log_frame, height=200, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True, padx=6, pady=6)

        try:
            if os.name == "nt":
                icon_path = resource_path("icon.ico")
                if os.path.exists(icon_path):
                    self.iconbitmap(icon_path)
                    self.after(100, lambda: self.wm_iconbitmap(icon_path))
            else:
                icon_path = resource_path("icon.png")
                if os.path.exists(icon_path):
                    icon_img = tk.PhotoImage(file=icon_path)
                    self.iconphoto(True, icon_img)

            self.preview_img_path = resource_path("preview.png")
        except Exception as e:
            print(f"Failed to set icon: {e}")

        self.refresh_profiles()
        self.after(80, self._poll_log_queue)

    # UI helpers
    def pick_ue(self):
        path = filedialog.askopenfilename(
            title="Select UE4Editor.exe",
            filetypes=[
                ("UE4Editor", "UE4Editor.exe"),
                ("Executables", "*.exe"),
                ("All files", "*.*"),
            ],
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
                if messagebox.askyesno(
                    "Unusual Path",
                    f"'{raw}' doesn't look like a /Game/ package path.\nAdd anyway as plain text?",
                ):
                    self.items.append({"type": "asset", "value": raw})
                    self._refresh_listbox()
        self.asset_entry.delete(0, tk.END)

    def add_folder(self):
        folder = filedialog.askdirectory(title="Choose folder containing assets")
        if not folder:
            return
        folder_path = str(Path(folder).resolve())
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
                # Show folder as /Game/...
                fp = Path(it["value"]) if it.get("value") else None
                display = None
                if fp:
                    display = folder_to_game_path(fp, content_root)
                self.listbox.insert(tk.END, f"📁 {display if display else it['value']}")

    # Profiles
    def _profile_path(self, name: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip()) or DEFAULT_PROFILE_NAME
        return SCRIPT_DIR / f"EasyCook_{safe}.json"

    def refresh_profiles(self):
        files = sorted(SCRIPT_DIR.glob("EasyCook_*.json"))
        names = [f.stem.replace("EasyCook_", "") for f in files]
        if DEFAULT_PROFILE_NAME not in names:
            names.insert(0, DEFAULT_PROFILE_NAME)

        self.profile_selector.configure(values=names)
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

    # Asset resolution
    def _infer_content_root(self) -> Optional[Path]:
        proj = self.uproject_var.get().strip().strip('"')
        if proj and Path(proj).is_file():
            pr = Path(proj).resolve().parent
            c = pr / "Content"
            if c.exists():
                return c.resolve()
        return None

    def _resolve_items_to_assets(self, show_loading: bool = True) -> list[str]:
        assets_set = set(it["value"].strip() for it in self.items if it["type"] == "asset")

        folders = [Path(it["value"]) for it in self.items if it["type"] == "folder"]
        if not folders:
            return sorted(assets_set)

        content_root = self._infer_content_root()

        loading_win = None
        stop_flag = {"stop": False}

        def open_loading():
            nonlocal loading_win
            loading_win = ctk.CTkToplevel(self)
            loading_win.title("Scanning folders…")
            loading_win.geometry("360x120")
            loading_win.transient(self)
            loading_win.grab_set()
            ctk.CTkLabel(loading_win, text="Expanding folder(s) into assets…").pack(
                pady=(16, 8)
            )
            pb = ctk.CTkProgressBar(loading_win, mode="indeterminate")
            pb.pack(fill="x", padx=16)
            pb.start()
            ctk.CTkLabel(
                loading_win, text="This may take a moment for large folders."
            ).pack(pady=8)

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

        while not stop_flag["stop"]:
            if loading_win:
                loading_win.update()
            self.update()
            time.sleep(0.03)
        close_loading()
        return sorted(assets_set)

    # Build & actions
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

        args = [
            ue,
            project,
            "-run=cook",
            f"-targetplatform={platform}",
            "-cooksinglepackage",
        ]
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

        def q(a: str) -> str:
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
        self.run_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")

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
                    self.run_btn.configure(state="normal")
                    self.cancel_btn.configure(state="disabled")
                else:
                    self._log(msg)
        except queue.Empty:
            pass
        self.after(80, self._poll_log_queue)

    def _create_theme_mode_toggle(self):
        """Create a toggle for switching between light and dark mode"""
        theme_frame = ctk.CTkFrame(self)
        theme_frame.place(relx=0.97, rely=0.02, anchor="ne")

        switch_var = ctk.StringVar(
            value="Dark" if ctk.get_appearance_mode() == "Dark" else "Light"
        )
        switch = ctk.CTkSwitch(
            theme_frame,
            text="Dark Mode",
            command=self._toggle_theme_mode,
            variable=switch_var,
            onvalue="Dark",
            offvalue="Light",
        )
        switch.pack(padx=10, pady=5)
        self._theme_switch = switch

    def _toggle_theme_mode(self):
        """Toggle between light and dark mode"""
        new_mode = "Dark" if self._theme_switch.get() == "Dark" else "Light"
        ctk.set_appearance_mode(new_mode)

        if new_mode == "Dark":
            bg_color = ctk.ThemeManager.theme["CTkFrame"]["fg_color"][1]
            fg_color = "#DCE4EE"  
        else:
            bg_color = ctk.ThemeManager.theme["CTkFrame"]["fg_color"][0]
            fg_color = "#1A1A1A" 

        self.listbox.configure(bg=bg_color, fg=fg_color)

    def _apply_appearance_mode(self, value):
        """Apply the appearance mode to a color value"""
        if isinstance(value, (tuple, list)):
            if ctk.get_appearance_mode() == "Dark":
                return value[1] 
            else:
                return value[0]
        return value

    def _log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")


__all__ = ["App", "CollapsibleFrame"]
