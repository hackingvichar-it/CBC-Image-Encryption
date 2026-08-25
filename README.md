# CBC-Image-Encryption
This project is designed primarily for learning and demonstrating block cipher modes and how CBC operates on image data.

# 🔐 CBC Image Encryption & Decryption — CipherVision
CBC Image Encryption & Decryption is a Python-based educational cryptography project that demonstrates how AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode can be applied to digital images.

The project follows the CipherVision interface design, providing a modern dark-themed GUI for selecting images, entering or generating encryption keys, encrypting images, and decrypting them back using the original key.

# ✨ Features
🔒 AES-128-CBC image encryption
🔓 AES-128-CBC image decryption
🔑 Custom 16-character encryption key
⚡ Secure random 128-bit IV generation
🖼️ Supports common image formats such as PNG, JPG, JPEG, BMP, GIF, and TIFF
💾 Encrypted output stored as PNG
📦 IV stored in PNG metadata for decryption
📊 Session activity statistics
🎨 Modern dark-themed CipherVision GUI
👁️ Show/hide encryption key
⚡ Random key generator
✅ Input/output validation
🚨 Error and status handling

# 🛠️ Technologies Used
Python
Tkinter — Graphical User Interface
Pillow (PIL) — Image processing
PyCryptodome — AES cryptography
PNG Metadata — IV storage

# 📦 Installation

Install the required dependencies:
# if requirements.txt
pip install -r requirements.txt

# if not use 
pip install pillow pycryptodome

# Run the application:

python cbc_image.py
