import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, PngImagePlugin
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import secrets
import string


# ============================================================
# CIPHERVISION
# Secure Image Encryption / Decryption
# Version 2.0
# ============================================================


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

APP_NAME = "CipherVision"
APP_VERSION = "2.0"

# Main colors
BG = "#0B1120"
SIDEBAR = "#111827"
CARD = "#172033"
DARK_CARD = "#0F172A"
BORDER = "#263449"

# Text
WHITE = "#F8FAFC"
TEXT = "#CBD5E1"
MUTED = "#64748B"

# Accent
BLUE = "#3B82F6"
BLUE_HOVER = "#2563EB"

# Status
GREEN = "#22C55E"
RED = "#EF4444"
ORANGE = "#F59E0B"


# ============================================================
# AES-CBC ENCRYPTION
# ============================================================

def encrypt_image(input_path, output_path, key):
    """
    Encrypt an image using AES-128-CBC.

    The original CipherVision image workflow is preserved:
    - image converted to RGB
    - dimensions reduced to multiples of 16
    - ciphertext stored losslessly inside a PNG
    - random IV stored in PNG metadata

    The IV is not secret and is required for CBC decryption.
    """

    image = Image.open(input_path).convert("RGB")

    # Keep the same image-sizing behavior as the original GUI.
    width = (image.width // 16) * 16
    height = (image.height // 16) * 16

    if width == 0 or height == 0:
        raise ValueError(
            "Image is too small for AES processing."
        )

    image = image.resize(
        (width, height)
    )

    data = image.tobytes()

    # Because width and height are multiples of 16 and RGB uses
    # 3 bytes per pixel, the raw image data is block-aligned.
    if len(data) % AES.block_size != 0:
        raise ValueError(
            "Image data is not aligned to AES block size."
        )

    # Generate a fresh random 128-bit IV for every encryption.
    iv = get_random_bytes(
        AES.block_size
    )

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv
    )

    encrypted_data = cipher.encrypt(
        data
    )

    encrypted_image = Image.frombytes(
        "RGB",
        image.size,
        encrypted_data
    )

    # Store the IV in PNG metadata.
    # The IV is public/non-secret; the key remains private.
    metadata = PngImagePlugin.PngInfo()

    metadata.add_text(
        "CipherVision-Version",
        "2.0-CBC"
    )

    metadata.add_text(
        "CipherVision-Mode",
        "AES-128-CBC"
    )

    metadata.add_text(
        "CipherVision-IV",
        iv.hex()
    )

    metadata.add_text(
        "CipherVision-Width",
        str(width)
    )

    metadata.add_text(
        "CipherVision-Height",
        str(height)
    )

    # PNG is lossless, so ciphertext bytes are preserved exactly.
    encrypted_image.save(
        output_path,
        format="PNG",
        pnginfo=metadata
    )

    return output_path


# ============================================================
# AES-CBC DECRYPTION
# ============================================================

def decrypt_image(input_path, output_path, key):
    """
    Decrypt a CipherVision AES-128-CBC PNG.

    The IV is read from the PNG metadata written during
    encryption.
    """

    encrypted_image = Image.open(
        input_path
    ).convert("RGB")

    width = encrypted_image.width
    height = encrypted_image.height

    encrypted_data = encrypted_image.tobytes()

    if len(encrypted_data) % AES.block_size != 0:
        raise ValueError(
            "Invalid encrypted image data."
        )

    # Read the IV from the original PNG metadata.
    original = Image.open(
        input_path
    )

    iv_hex = original.info.get(
        "CipherVision-IV"
    )

    if not iv_hex:
        raise ValueError(
            "CipherVision CBC IV was not found in the PNG metadata."
        )

    try:
        iv = bytes.fromhex(
            iv_hex
        )
    except ValueError:
        raise ValueError(
            "Invalid CBC IV stored in the encrypted PNG."
        )

    if len(iv) != AES.block_size:
        raise ValueError(
            "Invalid CBC IV length."
        )

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=iv
    )

    decrypted_data = cipher.decrypt(
        encrypted_data
    )

    decrypted_image = Image.frombytes(
        "RGB",
        (width, height),
        decrypted_data
    )

    decrypted_image.save(
        output_path,
        format="PNG"
    )

    return output_path


# ============================================================
# MAIN APPLICATION
# ============================================================

class CipherVisionApp:

    def __init__(self, root):

        self.root = root

        # ----------------------------------------------------
        # Window
        # ----------------------------------------------------

        self.root.title(
            f"{APP_NAME} — Image Security"
        )

        self.root.geometry(
            "1150x720"
        )

        self.root.minsize(
            950,
            620
        )

        self.root.configure(
            bg=BG
        )

        # ----------------------------------------------------
        # Application state
        # ----------------------------------------------------

        self.current_page = None

        self.input_path = ""
        self.output_path = ""

        self.encryption_count = 0
        self.decryption_count = 0

        # ----------------------------------------------------
        # Create application
        # ----------------------------------------------------

        self.create_styles()

        self.create_main_layout()

        self.show_page(
            "Dashboard"
        )

        self.center_window()

    # ========================================================
    # STYLES
    # ========================================================

    def create_styles(self):

        style = ttk.Style()

        style.theme_use(
            "clam"
        )

        # Button

        style.configure(
            "TButton",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            padding=(
                14,
                9
            ),
            background=BLUE,
            foreground=WHITE,
            borderwidth=0
        )

        style.map(
            "TButton",
            background=[
                (
                    "active",
                    BLUE_HOVER
                ),
                (
                    "disabled",
                    "#334155"
                )
            ],
            foreground=[
                (
                    "disabled",
                    "#94A3B8"
                )
            ]
        )

        # Entry

        style.configure(
            "TEntry",
            fieldbackground="#0F172A",
            foreground=WHITE,
            insertcolor=WHITE,
            borderwidth=0,
            padding=10,
            font=(
                "Segoe UI",
                10
            )
        )

        # Progress

        style.configure(
            "TProgressbar",
            troughcolor="#0F172A",
            background=BLUE,
            thickness=6,
            borderwidth=0
        )

    # ========================================================
    # MAIN LAYOUT
    # ========================================================

    def create_main_layout(self):

        # ====================================================
        # SIDEBAR
        # ====================================================

        self.sidebar = tk.Frame(
            self.root,
            bg=SIDEBAR,
            width=245
        )

        self.sidebar.pack(
            side=tk.LEFT,
            fill=tk.Y
        )

        self.sidebar.pack_propagate(
            False
        )

        # ----------------------------------------------------
        # Logo
        # ----------------------------------------------------

        logo_frame = tk.Frame(
            self.sidebar,
            bg=SIDEBAR
        )

        logo_frame.pack(
            fill=tk.X,
            padx=22,
            pady=(
                28,
                35
            )
        )

        tk.Label(
            logo_frame,
            text="🔐",
            bg=SIDEBAR,
            fg=BLUE,
            font=(
                "Segoe UI Emoji",
                30
            )
        ).pack(
            side=tk.LEFT
        )

        logo_text = tk.Frame(
            logo_frame,
            bg=SIDEBAR
        )

        logo_text.pack(
            side=tk.LEFT,
            padx=10
        )

        tk.Label(
            logo_text,
            text="CipherVision",
            bg=SIDEBAR,
            fg=WHITE,
            font=(
                "Segoe UI",
                15,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            logo_text,
            text="IMAGE SECURITY",
            bg=SIDEBAR,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        # ====================================================
        # NAVIGATION
        # ====================================================

        self.nav_buttons = {}

        self.create_nav_button(
            "Dashboard",
            "⌂"
        )

        self.create_nav_button(
            "Encryption",
            "🔒"
        )

        self.create_nav_button(
            "Decryption",
            "🔓"
        )

        self.create_nav_button(
            "Activity",
            "📊"
        )

        self.create_nav_button(
            "Settings",
            "⚙"
        )

        # ====================================================
        # SYSTEM STATUS
        # ====================================================

        status_box = tk.Frame(
            self.sidebar,
            bg=DARK_CARD
        )

        status_box.pack(
            side=tk.BOTTOM,
            fill=tk.X,
            padx=18,
            pady=20
        )

        tk.Label(
            status_box,
            text="●  SYSTEM SECURE",
            bg=DARK_CARD,
            fg=GREEN,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=14,
            pady=(
                12,
                3
            )
        )

        tk.Label(
            status_box,
            text="Encryption engine ready",
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w",
            padx=14,
            pady=(
                0,
                12
            )
        )

        # ====================================================
        # CONTENT AREA
        # ====================================================

        self.content = tk.Frame(
            self.root,
            bg=BG
        )

        self.content.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

    # ========================================================
    # NAVIGATION BUTTON
    # ========================================================

    def create_nav_button(
        self,
        name,
        icon
    ):

        button = tk.Frame(
            self.sidebar,
            bg=SIDEBAR,
            height=48,
            cursor="hand2"
        )

        button.pack(
            fill=tk.X,
            padx=12,
            pady=3
        )

        button.pack_propagate(
            False
        )

        icon_label = tk.Label(
            button,
            text=icon,
            bg=SIDEBAR,
            fg=MUTED,
            font=(
                "Segoe UI Emoji",
                15
            ),
            width=3
        )

        icon_label.pack(
            side=tk.LEFT,
            padx=(
                8,
                0
            )
        )

        text_label = tk.Label(
            button,
            text=name,
            bg=SIDEBAR,
            fg=TEXT,
            font=(
                "Segoe UI",
                10
            )
        )

        text_label.pack(
            side=tk.LEFT
        )

        # ----------------------------------------------------
        # Bind entire navigation item
        # ----------------------------------------------------

        for widget in (
            button,
            icon_label,
            text_label
        ):

            widget.bind(
                "<Button-1>",
                lambda event,
                page=name:
                self.show_page(page)
            )

        self.nav_buttons[name] = (
            button,
            icon_label,
            text_label
        )

    # ========================================================
    # PAGE SWITCHING
    # ========================================================

    def show_page(
        self,
        page
    ):

        self.current_page = page

        # Remove old page

        for widget in self.content.winfo_children():

            widget.destroy()

        # ----------------------------------------------------
        # Update sidebar
        # ----------------------------------------------------

        for name, widgets in self.nav_buttons.items():

            frame, icon, label = widgets

            if name == page:

                frame.configure(
                    bg="#24334A"
                )

                icon.configure(
                    bg="#24334A",
                    fg=BLUE
                )

                label.configure(
                    bg="#24334A",
                    fg=WHITE,
                    font=(
                        "Segoe UI",
                        10,
                        "bold"
                    )
                )

            else:

                frame.configure(
                    bg=SIDEBAR
                )

                icon.configure(
                    bg=SIDEBAR,
                    fg=MUTED
                )

                label.configure(
                    bg=SIDEBAR,
                    fg=TEXT,
                    font=(
                        "Segoe UI",
                        10
                    )
                )

        # ----------------------------------------------------
        # Create requested page
        # ----------------------------------------------------

        if page == "Dashboard":

            self.create_dashboard()

        elif page == "Encryption":

            self.create_encryption_page()

        elif page == "Decryption":

            self.create_decryption_page()

        elif page == "Activity":

            self.create_activity_page()

        elif page == "Settings":

            self.create_settings_page()

    # ========================================================
    # PAGE HEADER
    # ========================================================

    def page_header(
        self,
        title,
        subtitle
    ):

        header = tk.Frame(
            self.content,
            bg=BG
        )

        header.pack(
            fill=tk.X,
            padx=35,
            pady=(
                30,
                25
            )
        )

        tk.Label(
            header,
            text=title,
            bg=BG,
            fg=WHITE,
            font=(
                "Segoe UI",
                25,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            header,
            text=subtitle,
            bg=BG,
            fg=MUTED,
            font=(
                "Segoe UI",
                10
            )
        ).pack(
            anchor="w",
            pady=(
                5,
                0
            )
        )

    # ========================================================
    # DASHBOARD
    # ========================================================

    def create_dashboard(self):

        self.page_header(
            "Dashboard",
            "Welcome to your image security workspace."
        )

        container = tk.Frame(
            self.content,
            bg=BG
        )

        container.pack(
            fill=tk.BOTH,
            expand=True,
            padx=35
        )

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        stats = tk.Frame(
            container,
            bg=BG
        )

        stats.pack(
            fill=tk.X
        )

        self.stat_card(
            stats,
            "🔒",
            "Images Encrypted",
            str(
                self.encryption_count
            )
        )

        self.stat_card(
            stats,
            "🔓",
            "Images Decrypted",
            str(
                self.decryption_count
            )
        )

        self.stat_card(
            stats,
            "⚡",
            "Encryption",
            "AES-128 CBC"
        )

        # ----------------------------------------------------
        # Welcome card
        # ----------------------------------------------------

        welcome = tk.Frame(
            container,
            bg=CARD
        )

        welcome.pack(
            fill=tk.BOTH,
            expand=True,
            pady=25
        )

        tk.Label(
            welcome,
            text="🔐  Secure Your Images",
            bg=CARD,
            fg=WHITE,
            font=(
                "Segoe UI",
                20,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=30,
            pady=(
                30,
                10
            )
        )

        tk.Label(
            welcome,
            text=(
                "CipherVision provides an educational interface "
                "for AES-based image encryption and decryption."
            ),
            bg=CARD,
            fg=TEXT,
            font=(
                "Segoe UI",
                11
            )
        ).pack(
            anchor="w",
            padx=30
        )

        buttons = tk.Frame(
            welcome,
            bg=CARD
        )

        buttons.pack(
            anchor="w",
            padx=30,
            pady=25
        )

        ttk.Button(
            buttons,
            text="🔒  Encrypt Image",
            command=lambda:
            self.show_page(
                "Encryption"
            )
        ).pack(
            side=tk.LEFT
        )

        ttk.Button(
            buttons,
            text="🔓  Decrypt Image",
            command=lambda:
            self.show_page(
                "Decryption"
            )
        ).pack(
            side=tk.LEFT,
            padx=10
        )

    # ========================================================
    # STAT CARD
    # ========================================================

    def stat_card(
        self,
        parent,
        icon,
        title,
        value
    ):

        card = tk.Frame(
            parent,
            bg=CARD
        )

        card.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=5
        )

        tk.Label(
            card,
            text=icon,
            bg=CARD,
            fg=BLUE,
            font=(
                "Segoe UI Emoji",
                24
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(
                18,
                3
            )
        )

        tk.Label(
            card,
            text=title,
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            anchor="w",
            padx=20
        )

        tk.Label(
            card,
            text=value,
            bg=CARD,
            fg=WHITE,
            font=(
                "Segoe UI",
                15,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(
                2,
                18
            )
        )

    # ========================================================
    # ENCRYPTION PAGE
    # ========================================================

    def create_encryption_page(self):

        self.page_header(
            "Image Encryption",
            "Encrypt an image using AES-CBC and your own 16-character AES key."
        )

        main = tk.Frame(
            self.content,
            bg=BG
        )

        main.pack(
            fill=tk.BOTH,
            expand=True,
            padx=35
        )

        # Left panel

        left = tk.Frame(
            main,
            bg=CARD
        )

        left.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=(
                0,
                10
            )
        )

        self.create_encryption_file_panel(
            left
        )

        # Right panel

        right = tk.Frame(
            main,
            bg=CARD
        )

        right.pack(
            side=tk.RIGHT,
            fill=tk.BOTH,
            expand=True,
            padx=(
                10,
                0
            )
        )

        self.create_encryption_key_panel(
            right
        )

    # ========================================================
    # ENCRYPTION FILE PANEL
    # ========================================================

    def create_encryption_file_panel(
        self,
        parent
    ):

        tk.Label(
            parent,
            text="IMAGE FILE",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                10
            )
        )

        select_box = tk.Frame(
            parent,
            bg=DARK_CARD
        )

        select_box.pack(
            fill=tk.X,
            padx=25
        )

        tk.Label(
            select_box,
            text="🖼",
            bg=DARK_CARD,
            fg=BLUE,
            font=(
                "Segoe UI Emoji",
                35
            )
        ).pack(
            pady=(
                20,
                5
            )
        )

        tk.Label(
            select_box,
            text="Choose image",
            bg=DARK_CARD,
            fg=WHITE,
            font=(
                "Segoe UI",
                12,
                "bold"
            )
        ).pack()

        tk.Label(
            select_box,
            text="PNG • JPG • JPEG • BMP • TIFF",
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            pady=5
        )

        ttk.Button(
            select_box,
            text="Browse Image",
            command=self.browse_input
        ).pack(
            pady=(
                5,
                20
            )
        )

        # Input

        tk.Label(
            parent,
            text="INPUT",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                18,
                4
            )
        )

        self.input_entry = ttk.Entry(
            parent
        )

        self.input_entry.pack(
            fill=tk.X,
            padx=25
        )

        # Output

        tk.Label(
            parent,
            text="OUTPUT",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                15,
                4
            )
        )

        output_frame = tk.Frame(
            parent,
            bg=CARD
        )

        output_frame.pack(
            fill=tk.X,
            padx=25
        )

        self.output_entry = ttk.Entry(
            output_frame
        )

        self.output_entry.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        ttk.Button(
            output_frame,
            text="...",
            width=3,
            command=self.browse_output
        ).pack(
            side=tk.RIGHT,
            padx=(
                8,
                0
            )
        )

        self.file_status = tk.Label(
            parent,
            text="No image selected",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        )

        self.file_status.pack(
            anchor="w",
            padx=25,
            pady=10
        )

    # ========================================================
    # ENCRYPTION KEY PANEL
    # ========================================================

    def create_encryption_key_panel(
        self,
        parent
    ):

        tk.Label(
            parent,
            text="ENCRYPTION SETTINGS",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                10
            )
        )

        # AES information

        info_card = tk.Frame(
            parent,
            bg=DARK_CARD
        )

        info_card.pack(
            fill=tk.X,
            padx=25
        )

        tk.Label(
            info_card,
            text="🔐",
            bg=DARK_CARD,
            fg=BLUE,
            font=(
                "Segoe UI Emoji",
                28
            )
        ).pack(
            side=tk.LEFT,
            padx=15,
            pady=15
        )

        info = tk.Frame(
            info_card,
            bg=DARK_CARD
        )

        info.pack(
            side=tk.LEFT
        )

        tk.Label(
            info,
            text="AES-128 / CBC",
            bg=DARK_CARD,
            fg=WHITE,
            font=(
                "Segoe UI",
                12,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            info,
            text="Custom 16-character key • Random IV",
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            info,
            text="IV stored in PNG metadata",
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w"
        )

        # Key

        tk.Label(
            parent,
            text="KEY — 16 CHARACTERS",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                5
            )
        )

        key_frame = tk.Frame(
            parent,
            bg=CARD
        )

        key_frame.pack(
            fill=tk.X,
            padx=25
        )

        self.key_entry = ttk.Entry(
            key_frame,
            show="•"
        )

        self.key_entry.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        self.show_key_var = tk.BooleanVar(
            value=False
        )

        tk.Checkbutton(
            key_frame,
            text="Show",
            variable=self.show_key_var,
            command=self.toggle_key,
            bg=CARD,
            fg=TEXT,
            activebackground=CARD,
            activeforeground=WHITE,
            selectcolor=CARD,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side=tk.RIGHT,
            padx=(
                8,
                0
            )
        )

        # Generate key

        ttk.Button(
            parent,
            text="⚡ Generate Random 16-Character Key",
            command=self.generate_key
        ).pack(
            fill=tk.X,
            padx=25,
            pady=(
                10,
                5
            )
        )

        tk.Label(
            parent,
            text=(
                "Save your key securely. You need the same "
                "key to decrypt the image."
            ),
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            ),
            wraplength=380,
            justify="left"
        ).pack(
            anchor="w",
            padx=25
        )

        # Status

        tk.Label(
            parent,
            text="ENCRYPTION STATUS",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                5
            )
        )

        self.progress = ttk.Progressbar(
            parent,
            mode="indeterminate"
        )

        self.progress.pack(
            fill=tk.X,
            padx=25
        )

        self.status_label = tk.Label(
            parent,
            text="● Ready",
            bg=CARD,
            fg=GREEN,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        )

        self.status_label.pack(
            anchor="w",
            padx=25,
            pady=8
        )

        # Encrypt

        self.encrypt_btn = ttk.Button(
            parent,
            text="🔒  ENCRYPT IMAGE",
            command=self.encrypt
        )

        self.encrypt_btn.pack(
            fill=tk.X,
            padx=25,
            pady=(
                10,
                8
            )
        )

        ttk.Button(
            parent,
            text="CLEAR",
            command=self.clear_fields
        ).pack(
            fill=tk.X,
            padx=25
        )

        # Warning

        tk.Label(
            parent,
            text=(
                "ⓘ Educational mode: AES-CBC is used for "
                "demonstration. AES-GCM is recommended for "
                "real-world secure applications."
            ),
            bg=CARD,
            fg=ORANGE,
            wraplength=380,
            justify="left",
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=20
        )

    # ========================================================
    # DECRYPTION PAGE
    # ========================================================

    def create_decryption_page(self):

        self.page_header(
            "Image Decryption",
            "Restore an AES-CBC encrypted image using the original key."
        )

        main = tk.Frame(
            self.content,
            bg=BG
        )

        main.pack(
            fill=tk.BOTH,
            expand=True,
            padx=35
        )

        # ----------------------------------------------------
        # Left
        # ----------------------------------------------------

        left = tk.Frame(
            main,
            bg=CARD
        )

        left.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=(
                0,
                10
            )
        )

        tk.Label(
            left,
            text="ENCRYPTED IMAGE",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                10
            )
        )

        select_box = tk.Frame(
            left,
            bg=DARK_CARD
        )

        select_box.pack(
            fill=tk.X,
            padx=25
        )

        tk.Label(
            select_box,
            text="🔐",
            bg=DARK_CARD,
            fg=BLUE,
            font=(
                "Segoe UI Emoji",
                35
            )
        ).pack(
            pady=(
                20,
                5
            )
        )

        tk.Label(
            select_box,
            text="Choose encrypted image",
            bg=DARK_CARD,
            fg=WHITE,
            font=(
                "Segoe UI",
                12,
                "bold"
            )
        ).pack()

        tk.Label(
            select_box,
            text="PNG encrypted with CipherVision AES-CBC",
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            pady=5
        )

        ttk.Button(
            select_box,
            text="Browse Encrypted Image",
            command=self.browse_decryption_input
        ).pack(
            pady=(
                5,
                20
            )
        )

        # Input

        tk.Label(
            left,
            text="ENCRYPTED INPUT",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                18,
                4
            )
        )

        self.decrypt_input_entry = ttk.Entry(
            left
        )

        self.decrypt_input_entry.pack(
            fill=tk.X,
            padx=25
        )

        # Output

        tk.Label(
            left,
            text="DECRYPTED OUTPUT",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                15,
                4
            )
        )

        output_frame = tk.Frame(
            left,
            bg=CARD
        )

        output_frame.pack(
            fill=tk.X,
            padx=25
        )

        self.decrypt_output_entry = ttk.Entry(
            output_frame
        )

        self.decrypt_output_entry.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        ttk.Button(
            output_frame,
            text="...",
            width=3,
            command=self.browse_decryption_output
        ).pack(
            side=tk.RIGHT,
            padx=(
                8,
                0
            )
        )

        self.decrypt_file_status = tk.Label(
            left,
            text="No encrypted image selected",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        )

        self.decrypt_file_status.pack(
            anchor="w",
            padx=25,
            pady=10
        )

        # ----------------------------------------------------
        # Right
        # ----------------------------------------------------

        right = tk.Frame(
            main,
            bg=CARD
        )

        right.pack(
            side=tk.RIGHT,
            fill=tk.BOTH,
            expand=True,
            padx=(
                10,
                0
            )
        )

        tk.Label(
            right,
            text="DECRYPTION SETTINGS",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                10
            )
        )

        # Key info

        key_info = tk.Frame(
            right,
            bg=DARK_CARD
        )

        key_info.pack(
            fill=tk.X,
            padx=25
        )

        tk.Label(
            key_info,
            text="🔑",
            bg=DARK_CARD,
            fg=BLUE,
            font=(
                "Segoe UI Emoji",
                28
            )
        ).pack(
            side=tk.LEFT,
            padx=15,
            pady=15
        )

        info = tk.Frame(
            key_info,
            bg=DARK_CARD
        )

        info.pack(
            side=tk.LEFT
        )

        tk.Label(
            info,
            text="Original Encryption Key",
            bg=DARK_CARD,
            fg=WHITE,
            font=(
                "Segoe UI",
                12,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            info,
            text="Enter the same key used for encryption.",
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            info,
            text="CBC IV is read from PNG metadata.",
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w"
        )

        # Key label

        tk.Label(
            right,
            text="KEY — 16 CHARACTERS",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                5
            )
        )

        key_frame = tk.Frame(
            right,
            bg=CARD
        )

        key_frame.pack(
            fill=tk.X,
            padx=25
        )

        self.decrypt_key_entry = ttk.Entry(
            key_frame,
            show="•"
        )

        self.decrypt_key_entry.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        self.decrypt_show_key_var = tk.BooleanVar(
            value=False
        )

        tk.Checkbutton(
            key_frame,
            text="Show",
            variable=self.decrypt_show_key_var,
            command=self.toggle_decrypt_key,
            bg=CARD,
            fg=TEXT,
            activebackground=CARD,
            activeforeground=WHITE,
            selectcolor=CARD,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side=tk.RIGHT,
            padx=(
                8,
                0
            )
        )

        # Generate key warning

        tk.Label(
            right,
            text=(
                "Do not generate a new key here. "
                "Decryption requires the original key."
            ),
            bg=CARD,
            fg=MUTED,
            wraplength=380,
            justify="left",
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                8,
                0
            )
        )

        # Status

        tk.Label(
            right,
            text="DECRYPTION STATUS",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                5
            )
        )

        self.decrypt_progress = ttk.Progressbar(
            right,
            mode="indeterminate"
        )

        self.decrypt_progress.pack(
            fill=tk.X,
            padx=25
        )

        self.decrypt_status_label = tk.Label(
            right,
            text="● Ready",
            bg=CARD,
            fg=GREEN,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        )

        self.decrypt_status_label.pack(
            anchor="w",
            padx=25,
            pady=8
        )

        # Decrypt button

        self.decrypt_btn = ttk.Button(
            right,
            text="🔓  DECRYPT IMAGE",
            command=self.decrypt
        )

        self.decrypt_btn.pack(
            fill=tk.X,
            padx=25,
            pady=(
                10,
                8
            )
        )

        ttk.Button(
            right,
            text="CLEAR",
            command=self.clear_decryption_fields
        ).pack(
            fill=tk.X,
            padx=25
        )

        tk.Label(
            right,
            text=(
                "ⓘ The encrypted image must be a PNG produced "
                "by CipherVision. JPEG compression may corrupt "
                "encrypted data."
            ),
            bg=CARD,
            fg=ORANGE,
            wraplength=380,
            justify="left",
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=20
        )

    # ========================================================
    # ACTIVITY PAGE
    # ========================================================

    def create_activity_page(self):

        self.page_header(
            "Activity",
            "Encryption and decryption activity for this session."
        )

        container = tk.Frame(
            self.content,
            bg=BG
        )

        container.pack(
            fill=tk.BOTH,
            expand=True,
            padx=35
        )

        # ----------------------------------------------------
        # Encryption
        # ----------------------------------------------------

        self.stat_card(
            container,
            "🔒",
            "Images Encrypted",
            str(
                self.encryption_count
            )
        )

        # ----------------------------------------------------
        # Decryption
        # ----------------------------------------------------

        self.stat_card(
            container,
            "🔓",
            "Images Decrypted",
            str(
                self.decryption_count
            )
        )

        # Information card

        card = tk.Frame(
            container,
            bg=CARD
        )

        card.pack(
            fill=tk.BOTH,
            expand=True,
            pady=25
        )

        tk.Label(
            card,
            text="SESSION INFORMATION",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                15
            )
        )

        tk.Label(
            card,
            text=(
                f"Encryption operations: "
                f"{self.encryption_count}"
            ),
            bg=CARD,
            fg=TEXT,
            font=(
                "Segoe UI",
                11
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=5
        )

        tk.Label(
            card,
            text=(
                f"Decryption operations: "
                f"{self.decryption_count}"
            ),
            bg=CARD,
            fg=TEXT,
            font=(
                "Segoe UI",
                11
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=5
        )

        ttk.Button(
            card,
            text="Clear Session Statistics",
            command=self.clear_activity
        ).pack(
            anchor="w",
            padx=25,
            pady=20
        )

    # ========================================================
    # SETTINGS PAGE
    # ========================================================

    def create_settings_page(self):

        self.page_header(
            "Settings",
            "CipherVision application information and security settings."
        )

        card = tk.Frame(
            self.content,
            bg=CARD
        )

        card.pack(
            fill=tk.BOTH,
            expand=True,
            padx=35,
            pady=(
                0,
                30
            )
        )

        tk.Label(
            card,
            text="APPLICATION",
            bg=CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=25,
            pady=(
                25,
                15
            )
        )

        # Application

        self.setting_row(
            card,
            "Application",
            f"{APP_NAME} {APP_VERSION}"
        )

        # Algorithm

        self.setting_row(
            card,
            "Algorithm",
            "AES-128"
        )

        # Mode

        self.setting_row(
            card,
            "Mode",
            "CBC"
        )

        # Format

        self.setting_row(
            card,
            "Encrypted Format",
            "PNG"
        )

        self.setting_row(
            card,
            "IV",
            "Random 128-bit (PNG metadata)"
        )

        # Security

        tk.Label(
            card,
            text=(
                "⚠  Security Notice\n\n"
                "AES-CBC is included for educational purposes. "
                "ECB reveals patterns in structured data and "
                "should not be used for production image "
                "encryption. For a real application, consider "
                "AES-GCM with authenticated encryption."
            ),
            bg=DARK_CARD,
            fg=ORANGE,
            wraplength=700,
            justify="left",
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            fill=tk.X,
            padx=25,
            pady=25,
            ipadx=10,
            ipady=10
        )

    # ========================================================
    # SETTING ROW
    # ========================================================

    def setting_row(
        self,
        parent,
        name,
        value
    ):

        row = tk.Frame(
            parent,
            bg=DARK_CARD
        )

        row.pack(
            fill=tk.X,
            padx=25,
            pady=4
        )

        tk.Label(
            row,
            text=name,
            bg=DARK_CARD,
            fg=WHITE,
            font=(
                "Segoe UI",
                10,
                "bold"
            )
        ).pack(
            side=tk.LEFT,
            padx=15,
            pady=13
        )

        tk.Label(
            row,
            text=value,
            bg=DARK_CARD,
            fg=MUTED,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side=tk.RIGHT,
            padx=15
        )

    # ========================================================
    # BROWSE ENCRYPTION INPUT
    # ========================================================

    def browse_input(self):

        filename = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[
                (
                    "Image Files",
                    "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"
                ),
                (
                    "All Files",
                    "*.*"
                )
            ]
        )

        if not filename:
            return

        self.input_path = filename

        self.input_entry.delete(
            0,
            tk.END
        )

        self.input_entry.insert(
            0,
            filename
        )

        # Automatically suggest encrypted output

        base, ext = os.path.splitext(
            filename
        )

        output = (
            f"{base}_encrypted.png"
        )

        self.output_entry.delete(
            0,
            tk.END
        )

        self.output_entry.insert(
            0,
            output
        )

        # Image information

        try:

            image = Image.open(
                filename
            )

            size = os.path.getsize(
                filename
            ) / 1024

            self.file_status.config(
                text=(
                    f"✓ {image.width} × {image.height} px"
                    f"   •   {size:.1f} KB"
                ),
                fg=GREEN
            )

        except Exception:

            self.file_status.config(
                text="Image selected",
                fg=GREEN
            )

        self.status_label.config(
            text="● Image selected",
            fg=GREEN
        )

    # ========================================================
    # BROWSE ENCRYPTION OUTPUT
    # ========================================================

    def browse_output(self):

        filename = filedialog.asksaveasfilename(
            title="Save Encrypted Image",
            defaultextension=".png",
            filetypes=[
                (
                    "PNG Image",
                    "*.png"
                ),
                (
                    "All Files",
                    "*.*"
                )
            ]
        )

        if filename:

            self.output_entry.delete(
                0,
                tk.END
            )

            self.output_entry.insert(
                0,
                filename
            )

    # ========================================================
    # TOGGLE ENCRYPTION KEY
    # ========================================================

    def toggle_key(self):

        if self.show_key_var.get():

            self.key_entry.config(
                show=""
            )

        else:

            self.key_entry.config(
                show="•"
            )

    # ========================================================
    # GENERATE RANDOM KEY
    # ========================================================

    def generate_key(self):

        characters = (
            string.ascii_letters +
            string.digits
        )

        key = "".join(
            secrets.choice(
                characters
            )
            for _ in range(16)
        )

        self.key_entry.delete(
            0,
            tk.END
        )

        self.key_entry.insert(
            0,
            key
        )

        # Show generated key

        self.show_key_var.set(
            True
        )

        self.key_entry.config(
            show=""
        )

        self.status_label.config(
            text="● New key generated",
            fg=GREEN
        )

    # ========================================================
    # ENCRYPTION CLEAR
    # ========================================================

    def clear_fields(self):

        self.input_entry.delete(
            0,
            tk.END
        )

        self.output_entry.delete(
            0,
            tk.END
        )

        self.key_entry.delete(
            0,
            tk.END
        )

        self.file_status.config(
            text="No image selected",
            fg=MUTED
        )

        self.status_label.config(
            text="● Ready",
            fg=GREEN
        )

        self.input_path = ""
        self.output_path = ""

    # ========================================================
    # ENCRYPT
    # ========================================================

    def encrypt(self):

        input_path = (
            self.input_entry
            .get()
            .strip()
        )

        output_path = (
            self.output_entry
            .get()
            .strip()
        )

        key_str = (
            self.key_entry
            .get()
        )

        # ----------------------------------------------------
        # Validate input
        # ----------------------------------------------------

        if not input_path:

            messagebox.showwarning(
                "Image Required",
                "Please select an image first."
            )

            return

        if not os.path.isfile(
            input_path
        ):

            messagebox.showerror(
                "File Not Found",
                "The selected image does not exist."
            )

            return

        if not output_path:

            messagebox.showwarning(
                "Output Required",
                "Please specify an output file."
            )

            return

        # ----------------------------------------------------
        # Validate key
        # ----------------------------------------------------

        if len(key_str) != 16:

            messagebox.showerror(
                "Invalid Encryption Key",
                "The AES key must contain exactly 16 characters."
            )

            return

        # ----------------------------------------------------
        # Prevent same input/output
        # ----------------------------------------------------

        if (
            os.path.abspath(
                input_path
            )
            ==
            os.path.abspath(
                output_path
            )
        ):

            messagebox.showerror(
                "Invalid Output",
                "Input and output files must be different."
            )

            return

        # ----------------------------------------------------
        # Force PNG
        # ----------------------------------------------------

        output_ext = (
            os.path.splitext(
                output_path
            )[1].lower()
        )

        if output_ext != ".png":

            messagebox.showerror(
                "Invalid Output Format",
                "Encrypted images must be saved as PNG."
            )

            return

        key = key_str.encode(
            "utf-8"
        )

        # ----------------------------------------------------
        # Start
        # ----------------------------------------------------

        self.encrypt_btn.config(
            state=tk.DISABLED
        )

        self.status_label.config(
            text="● Encrypting image...",
            fg=ORANGE
        )

        self.progress.start(
            10
        )

        self.root.update_idletasks()

        try:

            encrypt_image(
                input_path,
                output_path,
                key
            )

            self.progress.stop()

            self.encryption_count += 1

            self.status_label.config(
                text="● Encryption successful",
                fg=GREEN
            )

            messagebox.showinfo(
                "Encryption Complete",
                "Image encrypted successfully!\n\n"
                f"Saved to:\n{output_path}\n\n"
                "Keep your encryption key safe."
            )

        except Exception as error:

            self.progress.stop()

            self.status_label.config(
                text="● Encryption failed",
                fg=RED
            )

            messagebox.showerror(
                "Encryption Failed",
                str(error)
            )

        finally:

            self.encrypt_btn.config(
                state=tk.NORMAL
            )

    # ========================================================
    # DECRYPTION INPUT
    # ========================================================

    def browse_decryption_input(self):

        filename = filedialog.askopenfilename(
            title="Select AES-CBC Encrypted Image",
            filetypes=[
                (
                    "PNG Images",
                    "*.png"
                ),
                (
                    "All Files",
                    "*.*"
                )
            ]
        )

        if not filename:
            return

        self.decrypt_input_entry.delete(
            0,
            tk.END
        )

        self.decrypt_input_entry.insert(
            0,
            filename
        )

        base, ext = os.path.splitext(
            filename
        )

        output = (
            f"{base}_decrypted.png"
        )

        self.decrypt_output_entry.delete(
            0,
            tk.END
        )

        self.decrypt_output_entry.insert(
            0,
            output
        )

        # Image information

        try:

            image = Image.open(
                filename
            )

            size = os.path.getsize(
                filename
            ) / 1024

            self.decrypt_file_status.config(
                text=(
                    f"✓ {image.width} × {image.height} px"
                    f"   •   {size:.1f} KB"
                ),
                fg=GREEN
            )

        except Exception:

            self.decrypt_file_status.config(
                text="Encrypted image selected",
                fg=GREEN
            )

        self.decrypt_status_label.config(
            text="● Encrypted image selected",
            fg=GREEN
        )

    # ========================================================
    # DECRYPTION OUTPUT
    # ========================================================

    def browse_decryption_output(self):

        filename = filedialog.asksaveasfilename(
            title="Save Decrypted Image",
            defaultextension=".png",
            filetypes=[
                (
                    "PNG Image",
                    "*.png"
                ),
                (
                    "All Files",
                    "*.*"
                )
            ]
        )

        if filename:

            self.decrypt_output_entry.delete(
                0,
                tk.END
            )

            self.decrypt_output_entry.insert(
                0,
                filename
            )

    # ========================================================
    # TOGGLE DECRYPTION KEY
    # ========================================================

    def toggle_decrypt_key(self):

        if self.decrypt_show_key_var.get():

            self.decrypt_key_entry.config(
                show=""
            )

        else:

            self.decrypt_key_entry.config(
                show="•"
            )

    # ========================================================
    # CLEAR DECRYPTION
    # ========================================================

    def clear_decryption_fields(self):

        self.decrypt_input_entry.delete(
            0,
            tk.END
        )

        self.decrypt_output_entry.delete(
            0,
            tk.END
        )

        self.decrypt_key_entry.delete(
            0,
            tk.END
        )

        self.decrypt_file_status.config(
            text="No encrypted image selected",
            fg=MUTED
        )

        self.decrypt_status_label.config(
            text="● Ready",
            fg=GREEN
        )

    # ========================================================
    # DECRYPT
    # ========================================================

    def decrypt(self):

        input_path = (
            self.decrypt_input_entry
            .get()
            .strip()
        )

        output_path = (
            self.decrypt_output_entry
            .get()
            .strip()
        )

        key_str = (
            self.decrypt_key_entry
            .get()
        )

        # ----------------------------------------------------
        # Validate input
        # ----------------------------------------------------

        if not input_path:

            messagebox.showwarning(
                "Encrypted Image Required",
                "Please select an AES-CBC encrypted image."
            )

            return

        if not os.path.isfile(
            input_path
        ):

            messagebox.showerror(
                "File Not Found",
                "The encrypted image does not exist."
            )

            return

        if not output_path:

            messagebox.showwarning(
                "Output Required",
                "Please specify where the decrypted image should be saved."
            )

            return

        # ----------------------------------------------------
        # Validate key
        # ----------------------------------------------------

        if len(key_str) != 16:

            messagebox.showerror(
                "Invalid Key",
                "The encryption key must contain exactly 16 characters."
            )

            return

        # ----------------------------------------------------
        # Prevent same file
        # ----------------------------------------------------

        if (
            os.path.abspath(
                input_path
            )
            ==
            os.path.abspath(
                output_path
            )
        ):

            messagebox.showerror(
                "Invalid Output",
                "Input and output files must be different."
            )

            return

        # ----------------------------------------------------
        # Output must be PNG
        # ----------------------------------------------------

        output_ext = (
            os.path.splitext(
                output_path
            )[1].lower()
        )

        if output_ext != ".png":

            messagebox.showerror(
                "Invalid Output Format",
                "Decrypted output should be saved as PNG."
            )

            return

        key = key_str.encode(
            "utf-8"
        )

        # ----------------------------------------------------
        # Start
        # ----------------------------------------------------

        self.decrypt_btn.config(
            state=tk.DISABLED
        )

        self.decrypt_status_label.config(
            text="● Decrypting image...",
            fg=ORANGE
        )

        self.decrypt_progress.start(
            10
        )

        self.root.update_idletasks()

        try:

            decrypt_image(
                input_path,
                output_path,
                key
            )

            self.decrypt_progress.stop()

            self.decryption_count += 1

            self.decrypt_status_label.config(
                text="● Decryption successful",
                fg=GREEN
            )

            messagebox.showinfo(
                "Decryption Complete",
                "Image decrypted successfully!\n\n"
                f"Saved to:\n{output_path}"
            )

        except Exception as error:

            self.decrypt_progress.stop()

            self.decrypt_status_label.config(
                text="● Decryption failed",
                fg=RED
            )

            messagebox.showerror(
                "Decryption Failed",
                "Unable to decrypt the image.\n\n"
                "Make sure:\n"
                "• The image was encrypted by CipherVision\n"
                "• The correct 16-character key was entered\n"
                "• The encrypted PNG was not modified\n"
                "• The encrypted file was not converted to JPEG\n\n"
                f"Technical error:\n{error}"
            )

        finally:

            self.decrypt_btn.config(
                state=tk.NORMAL
            )

    # ========================================================
    # CLEAR ACTIVITY
    # ========================================================

    def clear_activity(self):

        self.encryption_count = 0
        self.decryption_count = 0

        messagebox.showinfo(
            "Activity Cleared",
            "Session statistics have been cleared."
        )

        self.show_page(
            "Activity"
        )

    # ========================================================
    # CENTER WINDOW
    # ========================================================

    def center_window(self):

        self.root.update_idletasks()

        width = self.root.winfo_width()
        height = self.root.winfo_height()

        screen_width = (
            self.root.winfo_screenwidth()
        )

        screen_height = (
            self.root.winfo_screenheight()
        )

        x = (
            screen_width - width
        ) // 2

        y = (
            screen_height - height
        ) // 2

        self.root.geometry(
            f"{width}x{height}+{x}+{y}"
        )


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = CipherVisionApp(
        root
    )

    root.mainloop()