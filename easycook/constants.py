import sys
from pathlib import Path

import customtkinter as ctk

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

APP_TITLE = "EasyCook4"
APP_VERSION = "1.2.1"

SCRIPT_DIR = Path(sys.argv[0]).resolve().parent.parent / "profiles"

THEME_COLOR = {
    "primary": "#1F6AA5",
    "secondary": "#2E7D32",
    "danger": "#C62828",
    "warning": "#F57F17",
    "text_light": "#FFFFFF",
    "text_dark": "#1A1A1A",
}

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
