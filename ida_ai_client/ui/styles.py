"""
styles.py — Central design tokens, palettes, and QSS for the AI Analyser dialog.

The active theme lives in the module-level ``COLORS`` dict. ``apply_theme(name)``
swaps in a palette by mutating ``COLORS`` (and ``STATUS_COLOR``) IN PLACE, so the
references other modules imported (``from .styles import COLORS``) keep pointing at
the same live object. Custom paintEvent code reads ``COLORS`` at paint time, and
QSS-styled widgets re-pick up colours when ``main_qss()`` is re-applied.
"""

# ── Palettes ─────────────────────────────────────────────────────────────────
#
# Every palette defines the full token set. Keys:
#   bg_base   deepest surface (graph background)
#   bg_input  inputs / inset surfaces
#   bg_elev   main dialog surface
#   bg_card   secondary surface (pills, panels)
#   bg_card_hi raised surface — also the Analyse button fill (lighter than bg_elev)
#   border / border_hi / border_lo / border_soft   outline tones
#   text / text_dim / text_mute   foreground tones
#   accent / accent_hi / accent_lo   brand accent
#   analyzing / done / failed / skipped / warn   status colours
#   bubble    user chat-bubble background (accent-tinted)

PALETTES: dict[str, dict] = {
    # ── Dark ──────────────────────────────────────────────────────────────
    "Nord": {
        "bg_base": "#272c36", "bg_input": "#272c36", "bg_elev": "#2e3440",
        "bg_card": "#272c36", "bg_card_hi": "#3b4252",
        "border": "#3b4252", "border_hi": "#434c5e", "border_lo": "#1e222a",
        "border_soft": "#333a47",
        "text": "#d8dee9", "text_dim": "#aeb6c4", "text_mute": "#6c7689",
        "accent": "#88c0d0", "accent_hi": "#8fbcbb", "accent_lo": "#5e81ac",
        "analyzing": "#81a1c1", "done": "#a3be8c", "failed": "#bf616a",
        "skipped": "#6c7689", "warn": "#ebcb8b", "bubble": "#3b4252",
    },
    "Gruvbox Material": {
        "bg_base": "#1d2021", "bg_input": "#1d2021", "bg_elev": "#282828",
        "bg_card": "#1d2021", "bg_card_hi": "#3c3836",
        "border": "#3c3836", "border_hi": "#504945", "border_lo": "#161616",
        "border_soft": "#32302f",
        "text": "#d4be98", "text_dim": "#a89984", "text_mute": "#7c6f64",
        "accent": "#d8a657", "accent_hi": "#e3b577", "accent_lo": "#bb8c3f",
        "analyzing": "#7daea3", "done": "#a9b665", "failed": "#ea6962",
        "skipped": "#7c6f64", "warn": "#e78a4e", "bubble": "#3a342f",
    },
    "Tokyo Night": {
        "bg_base": "#16161e", "bg_input": "#16161e", "bg_elev": "#1a1b26",
        "bg_card": "#1f2335", "bg_card_hi": "#292e42",
        "border": "#2a2e3f", "border_hi": "#3b4261", "border_lo": "#0f0f16",
        "border_soft": "#222536",
        "text": "#a9b1d6", "text_dim": "#828bb8", "text_mute": "#565f89",
        "accent": "#7aa2f7", "accent_hi": "#9ec0ff", "accent_lo": "#5a7fd6",
        "analyzing": "#7dcfff", "done": "#9ece6a", "failed": "#f7768e",
        "skipped": "#565f89", "warn": "#e0af68", "bubble": "#2a3158",
    },
    "Catppuccin Mocha": {
        "bg_base": "#181825", "bg_input": "#181825", "bg_elev": "#1e1e2e",
        "bg_card": "#181825", "bg_card_hi": "#313244",
        "border": "#313244", "border_hi": "#45475a", "border_lo": "#11111b",
        "border_soft": "#292c3c",
        "text": "#cdd6f4", "text_dim": "#a6adc8", "text_mute": "#7f849c",
        "accent": "#cba6f7", "accent_hi": "#ddb6ff", "accent_lo": "#b48ee0",
        "analyzing": "#89b4fa", "done": "#a6e3a1", "failed": "#f38ba8",
        "skipped": "#7f849c", "warn": "#f9e2af", "bubble": "#3a2f4d",
    },
    "Midnight Purple": {   # the original theme, kept as an option
        "bg_base": "#0a0a0f", "bg_input": "#0a0a0f", "bg_elev": "#13131b",
        "bg_card": "#0e0e15", "bg_card_hi": "#1a1a24",
        "border": "#2a2a38", "border_hi": "#3c3c50", "border_lo": "#08080c",
        "border_soft": "#1f1f2a",
        "text": "#a4a4a4", "text_dim": "#8a8a96", "text_mute": "#52525b",
        "accent": "#a855f7", "accent_hi": "#c084fc", "accent_lo": "#7c33d4",
        "analyzing": "#3b82f6", "done": "#10b981", "failed": "#ef4444",
        "skipped": "#52525b", "warn": "#ec4899", "bubble": "#2d1552",
    },
    # ── Light ─────────────────────────────────────────────────────────────
    "Solarized Light": {
        "bg_base": "#eee8d5", "bg_input": "#eee8d5", "bg_elev": "#fdf6e3",
        "bg_card": "#f5eed6", "bg_card_hi": "#ffffff",
        "border": "#ddd5bd", "border_hi": "#cfc6a8", "border_lo": "#ece5cf",
        "border_soft": "#e7e0c9",
        "text": "#586e75", "text_dim": "#657b83", "text_mute": "#93a1a1",
        "accent": "#268bd2", "accent_hi": "#3a9ee0", "accent_lo": "#1e6fa8",
        "analyzing": "#268bd2", "done": "#859900", "failed": "#dc322f",
        "skipped": "#93a1a1", "warn": "#b58900", "bubble": "#e3eef7",
    },
    "Catppuccin Latte": {
        "bg_base": "#e6e9ef", "bg_input": "#e6e9ef", "bg_elev": "#eff1f5",
        "bg_card": "#e6e9ef", "bg_card_hi": "#ffffff",
        "border": "#ccd0da", "border_hi": "#bcc0cc", "border_lo": "#dce0e8",
        "border_soft": "#e6e9ef",
        "text": "#4c4f69", "text_dim": "#6c6f85", "text_mute": "#8c8fa1",
        "accent": "#8839ef", "accent_hi": "#9a52f0", "accent_lo": "#7028c8",
        "analyzing": "#1e66f5", "done": "#40a02b", "failed": "#d20f39",
        "skipped": "#8c8fa1", "warn": "#df8e1d", "bubble": "#e6d9fb",
    },
}

DEFAULT_THEME = "Tokyo Night"

# ── Live design tokens (mutated in place by apply_theme) ──────────────────────

COLORS: dict[str, str] = dict(PALETTES[DEFAULT_THEME])

STATUS_COLOR: dict[str, str] = {}

STATUS_LABEL = {
    "queued":    "Queued",
    "analysing": "Analysing…",
    "refining":  "Refining…",
    "analysed":  "Analysed",
    "done":      "Done",
    "no_notes":  "Done",
    "skipped":   "Skipped",
    "failed":    "Failed",
}


def _rebuild_status() -> None:
    """Re-derive STATUS_COLOR from the current COLORS (in place)."""
    STATUS_COLOR.clear()
    STATUS_COLOR.update({
        "queued":    COLORS["text_mute"],
        "analysing": COLORS["analyzing"],
        "refining":  COLORS["accent"],
        "analysed":  COLORS["done"],
        "done":      COLORS["done"],
        "no_notes":  COLORS["done"],
        "skipped":   COLORS["skipped"],
        "failed":    COLORS["failed"],
    })


def apply_theme(name: str) -> bool:
    """Switch the active palette by mutating COLORS / STATUS_COLOR in place.

    Returns True if the named theme exists, False if it fell back to default.
    Callers should re-apply main_qss() to open dialogs and repaint afterwards.
    """
    pal = PALETTES.get(name)
    ok = pal is not None
    if pal is None:
        pal = PALETTES[DEFAULT_THEME]
    COLORS.clear()
    COLORS.update(pal)
    _rebuild_status()
    return ok


def theme_names() -> list[str]:
    """Ordered list of selectable theme names (dark first, then light)."""
    return list(PALETTES.keys())


_rebuild_status()   # initialise STATUS_COLOR for the default theme

FONT_SANS = "Inter, 'Segoe UI', 'SF Pro Text', Roboto, sans-serif"
FONT_MONO = "'JetBrains Mono', 'Cascadia Code', Consolas, 'Courier New', monospace"

ROOT_RADIUS = 14   # window corner radius

MOTION_FAST_MS = 120
MOTION_NORMAL_MS = 180
MOTION_SLOW_MS = 360


def _qss_rgba(hex_color: str, alpha: float) -> str:
    value = hex_color.strip()
    if value.startswith("#") and len(value) == 7:
        r = int(value[1:3], 16)
        g = int(value[3:5], 16)
        b = int(value[5:7], 16)
        return f"rgba({r}, {g}, {b}, {alpha:.3f})"
    return value


# ── Main stylesheet ──────────────────────────────────────────────────────────

def main_qss() -> str:
    c = COLORS
    r = ROOT_RADIUS
    session_selected_bg = _qss_rgba(c["accent"], 0.16)
    session_selected_hover_bg = _qss_rgba(c["accent"], 0.22)
    session_selected_border = _qss_rgba(c["accent_hi"], 0.36)
    return f"""
    /* ── Dialog backstop — prevents palette grey leaking at mask edges ── */
    QDialog {{
        background: {c['bg_elev']};
    }}
    QDialog#analysisDialog {{
        background: transparent;
    }}

    /* ── Root surface ──────────────────────────────────────────────────── */
    QFrame#rootSurface {{
        background: {c['bg_elev']};
        border-radius: {r}px;
        border: 1px solid {c['border_hi']};
    }}
    QFrame#analysisRootSurface {{
        background: transparent;
        border: none;
        border-radius: {r}px;
    }}

    /* Container widgets — transparent so rootSurface background shows through */
    QWidget#compactBody, QWidget#expandedBody, QWidget#settingsBody {{
        background: transparent;
    }}

    /* ── Title bar ───────────────────────────────────────────────────── */
    #titleBar {{
        background: transparent;
        border-bottom: 1px solid {c['border']};
    }}
    #titleLabel {{
        color: {c['text_dim']};
        font-size: 12px;
        font-weight: 500;
        letter-spacing: 0.5px;
    }}
    QToolButton#iconBtn {{
        background: transparent;
        border: none;
        border-radius: 6px;
        color: {c['text_mute']};
        padding: 4px;
    }}
    QToolButton#iconBtn:hover {{
        background: {c['bg_card_hi']};
        color: {c['text']};
    }}
    QToolButton#iconBtn:pressed {{
        background: {c['bg_card']};
        color: {c['accent_hi']};
    }}
    QToolButton#iconBtn:focus {{
        border: 1px solid {c['accent']};
        padding: 3px;
    }}
    /* ── Target pill ─────────────────────────────────────────────────── */
    QToolButton#profileBtn {{
        background: {c['bg_card']};
        border: 1px solid {c['border_lo']};
        border-radius: 7px;
        color: {c['text_dim']};
        padding: 3px 8px;
        font-size: 11px;
        font-weight: 500;
    }}
    QToolButton#profileBtn:hover {{
        background: {c['bg_card_hi']};
        border-color: {c['border_hi']};
        color: {c['text']};
    }}
    QToolButton#profileBtn:pressed,
    QToolButton#profileBtn:focus {{
        border-color: {c['accent']};
        color: {c['text']};
    }}
    QToolButton#profileBtn:disabled {{
        background: {c['bg_card']};
        border-color: {c['border']};
        color: {c['text_mute']};
    }}
    QToolButton#updateBtn {{
        background: {c['accent']};
        border: 1px solid {c['accent']};
        border-radius: 7px;
        color: #ffffff;
        padding: 3px 9px;
        font-size: 11px;
        font-weight: 600;
    }}
    QToolButton#updateBtn:hover {{
        background: {c['accent_hi']};
        border-color: {c['accent_hi']};
    }}
    QToolButton#updateBtn:pressed {{
        background: {c['accent']};
    }}
    QToolButton#updateBtn:disabled {{
        background: {c['bg_card']};
        border-color: {c['border']};
        color: {c['text_mute']};
    }}

    QFrame#targetPill {{
        background: transparent;
        border: none;
        padding: 0;
    }}
    QLabel#targetLabel    {{ color: {c['text_mute']}; font-family: {FONT_MONO}; font-size: 11px; }}
    QLabel#targetName     {{ color: {c['text']};      font-family: {FONT_MONO}; font-size: 12px; }}
    QLabel#targetEA       {{ color: {c['accent']};    font-family: {FONT_MONO}; font-size: 12px; }}

    /* ── Prompt input ────────────────────────────────────────────────── */
    QTextEdit#promptInput {{
        background: {c['bg_input']};
        border: 1px solid {c['border_hi']};
        border-radius: 10px;
        padding: 11px 13px;
        color: {c['text']};
        font-family: {FONT_SANS};
        font-size: 13px;
        selection-background-color: {c['accent']};
    }}
    QTextEdit#promptInput:focus {{ border: 1px solid {c['border_hi']}; }}
    QTextEdit#chatInput {{
        background: transparent;
        border: none;
        border-radius: 0;
        padding: 2px 3px;
        color: {c['text']};
        font-family: {FONT_SANS};
        font-size: 13px;
        selection-background-color: {c['accent']};
    }}
    QTextEdit#chatInput:focus {{ border: none; }}
    QTextEdit#chatInput:disabled {{
        color: {c['text_mute']};
    }}
    QMenu#modelEffortMenu,
    QMenu#modelEffortSubmenu {{
        background: transparent;
        border: none;
        padding: 5px;
        color: {c['text']};
        font-family: {FONT_SANS};
        font-size: 12px;
    }}
    QMenu#modelEffortMenu::item {{
        min-height: 20px;
        padding: 7px 10px;
        border-radius: 6px;
        color: transparent;
    }}
    QMenu#modelEffortSubmenu::item {{
        min-height: 20px;
        padding: 7px 28px 7px 10px;
        border-radius: 6px;
        color: {c['text']};
    }}
    QMenu#modelEffortMenu::item:selected {{
        background: transparent;
        color: transparent;
    }}
    QMenu#modelEffortSubmenu::item:selected {{
        background: transparent;
        color: {c['accent_hi']};
    }}
    QMenu#modelEffortMenu::right-arrow {{
        image: none;
        width: 0px;
        height: 0px;
    }}
    QMenu#modelEffortSubmenu::indicator {{
        image: none;
        width: 0;
        height: 0;
    }}

    /* ── Hint text ───────────────────────────────────────────────────── */
    QLabel#hintLabel {{
        color: {c['text_mute']};
        font-family: {FONT_MONO};
        font-size: 10px;
    }}

    /* ── Toolbar (expanded state) ────────────────────────────────────── */
    #expandedToolbar {{
        background: {c['bg_elev']};
        border-bottom: 1px solid {c['border']};
    }}
    QLabel#promptSummary {{
        color: {c['text_dim']};
        font-size: 12px;
        font-style: italic;
    }}
    /* Vertical divider between the EA and the prompt summary. */
    QFrame#toolbarDivider {{
        background: {c['border']};
        border: none;
    }}

    /* ── Log panel — the graph/log divider is drawn by _SplitterHandle
          (a 1px line + centred grip), so no border-left here. ────────── */
    QFrame#logPanel {{
        background: {c['bg_elev']};
    }}
    QLabel#sectionHeader {{
        color: {c['text_mute']};
        font-family: {FONT_MONO};
        font-size: 10px;
        font-weight: 500;
        letter-spacing: 1.2px;
        padding: 12px 14px 10px 14px;
        border-bottom: 1px solid {c['border']};
    }}
    QTextEdit#logBody {{
        background: {c['bg_input']};
        border: none;
        margin-left: 1px;
        color: {c['text_dim']};
        font-family: {FONT_MONO};
        font-size: 11px;
        padding: 8px 14px;
        selection-background-color: {c['accent']};
    }}
    /* ── Chat thread scroll area ─────────────────────────────────────── */
    QScrollArea#chatScroll  {{ background: transparent; border: none; }}
    /* Opaque background required: when WorkingWidget shrinks during the log-pane
       collapse animation Qt must erase the vacated area.  Transparent backgrounds
       skip the erase step and leave ghost / double-text artefacts. */
    QWidget#chatContainer   {{ background: {c['bg_elev']}; }}

    /* ── Inline engine activity ─────────────────────────────────────── */
    QScrollArea#workingActivityPane,
    QScrollArea#workingActivityPane > QWidget > QWidget,
    QWidget#workingActivityContent {{
        background: transparent;
        border: none;
    }}
    QLabel#activityActionLabel {{
        color: {c['text_dim']};
        font-family: {FONT_SANS};
        font-size: 12px;
        background: transparent;
    }}
    QLabel#activityActionDetail {{
        color: {c['text_mute']};
        font-family: {FONT_MONO};
        font-size: 10px;
        background: transparent;
    }}
    /* ── Chat input row — the left divider + top border are drawn by
          _SplitterHandle (which blends into this row's bg), so no
          border-left here; it would double the divider line. ──────────── */
    QFrame#chatInputRow {{
        background: {c['bg_elev']};
        border: none;
    }}
    QFrame#chatComposer {{
        background: {c['bg_input']};
        border: 1px solid {c['border_hi']};
        border-radius: 16px;
    }}

    /* ── Drawer history (ConversationDrawer) ─────────────────────────── */
    QTextEdit#chatHistory {{
        background: {c['bg_input']};
        border: none;
        color: {c['text_dim']};
        font-family: {FONT_MONO};
        font-size: 11px;
        padding: 8px 14px;
        selection-background-color: {c['accent']};
    }}

    /* ── ConversationDrawer overlay ──────────────────────────────────── */
    QFrame#convDrawer  {{ background: {c['bg_elev']}; }}
    QFrame#drawerTab   {{ background: {c['bg_card_hi']}; }}
    QFrame#drawerPanel {{
        background: {c['bg_elev']};
        border-right: 1px solid {c['border_hi']};
    }}
    QStackedWidget#sessionContentStack,
    QWidget#sessionLoadingPage {{
        background: transparent;
        border: none;
    }}

    /* ── Session list (ConversationDrawer) ───────────────────────────── */
    QListWidget#sessionList {{
        background: transparent;
        border: none;
        outline: none;
        padding: 4px 0;
        color: {c['text_dim']};
        font-family: {FONT_SANS};
        font-size: 12px;
    }}
    QListWidget#sessionList::item {{
        padding: 0;
        margin: 2px 8px;
        border-radius: 6px;
        color: {c['text_dim']};
        border: 1px solid transparent;
    }}
    QListWidget#sessionList::item:hover {{
        background: {c['bg_card_hi']};
        color: {c['text']};
    }}
    QListWidget#sessionList::item:selected {{
        background: {session_selected_bg};
        border: 1px solid {session_selected_border};
        color: {c['accent_hi']};
    }}
    QListWidget#sessionList::item:selected:hover {{
        background: {session_selected_hover_bg};
        border: 1px solid {session_selected_border};
        color: {c['accent_hi']};
    }}
    QLabel#sessionLoadingLabel {{
        background: transparent;
        color: {c['text_mute']};
        font-size: 11px;
    }}
    QWidget#sessionRow,
    QToolButton#sessionRenameButton,
    QToolButton#sessionDeleteButton {{
        background: transparent;
        border: none;
        color: {c['text_mute']};
        font-size: 11px;
        padding: 0;
    }}
    QLabel#sessionRowLabel {{
        background: transparent;
        border: none;
        color: {c['text_dim']};
        font-size: 11px;
        padding: 0;
    }}
    QLabel#sessionRowLabel[active="true"] {{
        color: {c['accent_hi']};
        font-weight: 500;
    }}
    QToolButton#sessionRenameButton:hover {{
        color: {c['text']};
    }}
    QToolButton#sessionDeleteButton:hover {{
        color: {c['failed']};
    }}

    /* ── Settings dialog inputs ─────────────────────────────────────── */
    QWidget#settingsBody QFrame#settingsRow {{
        background: transparent;
        border: none;
        border-radius: 7px;
    }}
    QWidget#settingsBody QFrame#settingsRow:hover {{
        background: {c['bg_card_hi']};
    }}
    QWidget#settingsBody QFrame#settingsRow QLabel#settingsRowLabel {{
        background: transparent;
        color: {c['text']};
        font-family: {FONT_SANS};
        font-size: 12px;
    }}
    QWidget#settingsBody QFrame#settingsGroup {{
        background: transparent;
        border: none;
    }}

    QLineEdit, QSpinBox {{
        background: {c['bg_input']};
        border: 1px solid {c['border_hi']};
        border-radius: 7px;
        color: {c['text']};
        font-family: {FONT_SANS};
        font-size: 12px;
        selection-background-color: {c['accent']};
    }}
    QLineEdit {{ padding: 6px 9px; }}
    QSpinBox {{ padding: 6px 34px 6px 9px; }}
    QLineEdit:focus, QSpinBox:focus {{ border: 1px solid {c['accent']}; }}
    QLineEdit:disabled, QSpinBox:disabled {{
        background: {c['bg_card']};
        border-color: {c['border']};
        color: {c['text_mute']};
    }}
    QSpinBox::up-button, QSpinBox::down-button {{
        width: 0;
        height: 0;
        border: none;
        background: transparent;
    }}

    /* ── Combo boxes (model tier, theme) ────────────────────────────── */
    QComboBox {{
        background: {c['bg_input']};
        border: 1px solid {c['border_hi']};
        border-radius: 7px;
        padding: 5px 34px 5px 9px;
        color: {c['text']};
        font-family: {FONT_SANS};
        font-size: 12px;
        min-height: 18px;
    }}
    QComboBox:hover {{ border: 1px solid {c['accent']}; }}
    QComboBox:focus {{ border: 1px solid {c['accent']}; }}
    QComboBox:disabled {{
        background: {c['bg_card']};
        border-color: {c['border']};
        color: {c['text_mute']};
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: center right;
        width: 22px;
        border: none;
        background: transparent;
    }}
    QComboBox::down-arrow {{
        image: none;
        width: 0;
        height: 0;
        border: none;
    }}
    /* The popup list. */
    QComboBox QAbstractItemView {{
        background: {c['bg_card']};
        border: 1px solid {c['border_hi']};
        border-radius: 7px;
        color: {c['text']};
        padding: 4px;
        outline: none;
        selection-background-color: {c['accent']};
        selection-color: {c['bg_elev']};
    }}
    QComboBox QAbstractItemView::item {{
        padding: 5px 8px;
        border-radius: 5px;
        min-height: 20px;
    }}
    /* Currently-selected item (highlighted before any hover) — themed accent
       instead of the system/palette highlight. Listed before :hover so hover
       still wins when the selected item is also hovered. */
    QComboBox QAbstractItemView::item:selected {{
        background: {c['accent']};
        color: {c['bg_elev']};
    }}
    QComboBox QAbstractItemView::item:hover {{
        background: {c['bg_card_hi']};
        color: {c['text']};
    }}

    QCheckBox {{
        color: {c['text']};
        font-size: 12px;
        spacing: 0;
        padding: 0;
        background: transparent;
    }}
    QCheckBox::indicator {{
        width: 14px; height: 14px;
        border-radius: 4px;
        border: 1px solid {c['border_hi']};
        background: {c['bg_input']};
    }}
    QCheckBox::indicator:checked {{
        background: {c['accent']};
        border: 1px solid {c['accent_lo']};
    }}
    QCheckBox:focus {{
        color: {c['accent_hi']};
    }}
    QCheckBox:disabled {{
        color: {c['text_mute']};
    }}

    /* ── Group box ─────────────────────────────────────────────────── */
    QGroupBox {{
        color: {c['text_dim']};
        font-size: 11px;
        font-weight: 500;
        letter-spacing: 0.8px;
        background: {c['bg_card']};
        border: 1px solid {c['border_hi']};
        border-radius: 9px;
        padding: 18px 12px 12px 12px;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 12px;
        padding: 0 6px;
        background: {c['bg_elev']};
    }}
    QLabel {{ color: {c['text']}; }}

    /* ── Node info panel (graph overlay) ─────────────────────────────── */
    QFrame#nodeInfoPanel {{
        background: {c['bg_card']};
        border: 1px solid {c['border_hi']};
        border-radius: 10px;
    }}

    /* ── Message boxes ───────────────────────────────────────────────── */
    QMessageBox {{
        background: {c['bg_elev']};
        color: {c['text']};
    }}
    QMessageBox QPushButton {{
        background: {c['bg_card_hi']};
        border: 1px solid {c['border']};
        color: {c['text']};
        border-radius: 7px;
        padding: 6px 16px;
        font-size: 12px;
        min-width: 70px;
    }}
    QMessageBox QPushButton:hover {{ border-color: {c['accent']}; color: {c['accent']}; }}

    QToolTip {{
        background: {c['bg_card_hi']};
        color: {c['text']};
        border: 1px solid {c['border_hi']};
        padding: 5px 7px;
    }}
    """
