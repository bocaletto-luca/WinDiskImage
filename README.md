# WinDiskImage

**WinDiskImage** is a lightweight, user-friendly disk imaging tool for Windows, built with Python and PySide6.  
It allows you to **create** and **restore** raw disk images from physical drives, with real-time progress, speed, and ETA display.

---

## ✨ Features

- 📀 **Create disk images** from physical drives
- 🔄 **Restore disk images** to physical drives
- 📊 Real-time **progress bar**, **speed**, and **ETA**
- 📝 Detailed logging of operations
- 🛑 Cancel ongoing operations safely
- 🖥️ Simple, intuitive **GUI** built with PySide6
- 🪟 Designed for **Windows** (requires Administrator privileges)

---

## 📦 Requirements

- **Python** 3.9 or newer
- **PySide6** for the GUI
- Windows OS (tested on Windows 10/11)
- Administrator privileges for disk access

---

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bocaletto-luca/WinDiskImage.git
   cd WinDiskImage
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python WinDiskImage.py
   ```

> 💡 **Tip:** Always run the application as **Administrator** to ensure proper disk access.

---

## 📂 Project Structure

```
WinDiskImage/
├── WinDiskImage.py     # Main application
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
└── LICENSE             # GPL v3 license
```

---

## ⚠️ Usage Notes

- **Data loss warning:** Restoring an image will overwrite the target disk completely. Double-check the selected device before proceeding.
- **Performance:** Imaging speed depends on disk type, interface (USB/SATA/NVMe), and system load.
- **File format:** Images are stored as raw `.img` files, compatible with many other imaging tools.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

```
WinDiskImage - A Windows disk imaging tool
Copyright (C) 2025  Luca Bocaletto

This program is free software: you can redistribute it and/or modify  
it under the terms of the GNU General Public License as published by  
the Free Software Foundation, either version 3 of the License, or  
(at your option) any later version.

This program is distributed in the hope that it will be useful,  
but WITHOUT ANY WARRANTY; without even the implied warranty of  
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  
GNU General Public License for more details.

You should have received a copy of the GNU General Public License  
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

---

## 👤 Author

**Luca Bocaletto**  
GitHub: [@bocaletto-luca](https://github.com/bocaletto-luca)

---

## 🚀 Future Improvements

- Multi-threaded read/write for faster imaging
- Compression support for image files
- Cross-platform support (Linux/macOS)
- Image verification after creation

---

## 🤝 Contributing

Contributions are welcome!  
If you’d like to improve **WinDiskImage**, please fork the repository and submit a pull request.

---

## 🐞 Issues

If you encounter a bug or have a feature request, please open an issue here:  
[https://github.com/bocaletto-luca/WinDiskImage/issues](https://github.com/bocaletto-luca/WinDiskImage/issues)


If you want, I can also prepare the **`requirements.txt`** and **`LICENSE`** file so your repo is instantly ready for publishing under GPL v3.  
Do you want me to generate those next?
