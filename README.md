# 🔧 Reverse Engineering Toolkit

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Language](https://img.shields.io/badge/Languages-EN%20|%20RU-blue)](LANGUAGE.md)

**Comprehensive toolkit for reverse engineering and anti-cheat protection analysis**

> ⚠️ **IMPORTANT:** This tool is for educational and security research purposes only. Use responsibly and legally.

## 🌍 Multi-Language Support

This application supports **English** and **Russian** languages!

**To switch language:** Open menu `Tools` → `Language` (or `Инструменты` → `Язык`)

The entire interface will switch instantly including:
- All menus and buttons
- All dialog windows  
- All status messages
- All error messages
- All table headers

## ⚠️ LEGAL USE ONLY

This tool is created **exclusively for legitimate purposes**:
- ✅ Research and improvement of anti-cheat systems
- ✅ Security analysis of your own software
- ✅ Educational purposes
- ❌ **NOT** for creating game cheats
- ❌ **NOT** for violating license agreements

## 🚀 Features

### 1. 📋 PE Analyzer
Deep analysis of PE executable files (EXE/DLL):
- Parse DOS and PE headers
- Analyze sections (code, data, resources)
- View import table (which DLLs and functions the program uses)
- View export table (which functions a DLL provides)
- Support for both x86 (32-bit) and x64 (64-bit) formats
- Export analysis results to text file

### 2. 🔢 Hex Editor
View and edit binary files:
- Display in hex format with ASCII representation
- Search for byte patterns (in hex or text format)
- Jump to specific offset
- Edit bytes directly
- Auto-detect file type by signature

### 3. 🧠 Memory Scanner
Scan and modify memory of running processes:
- Attach to any process (requires administrator rights)
- Search for values in memory (integers, float, double, strings)
- Multiple scans to narrow down results
- Modify values in real-time
- Freeze values (constantly maintain a specific value)

**How to use:**
1. **RUN the program as administrator!**
2. Open "Memory Scanner" tab
3. Click "Refresh list" and select target process
4. Enter known value and click "First Scan"
5. Change value in game/program
6. Enter new value and click "Next Scan"
7. Repeat until you get 1-10 results

### 4. 🔍 Pattern Scanner
Search for byte patterns with wildcard support:
- Search for signatures in files and process memory
- Wildcard support (?) for unknown bytes
- Example: `E8 ? ? ? ?` finds all CALL instructions

### 5. ⚙️ Disassembler
Disassemble machine code to assembly:
- Support for x86 and x64 architectures
- Automatic instruction recognition
- Comments on important operations

### 6. 🌐 Network Monitor ⭐ KEY FEATURE
**Monitor network activity of processes - track servers and downloads:**

- Track TCP and UDP connections of specific process
- Automatic DNS name resolution and server type detection
- **Recognize server types:**
  - 🎮 Game Server
  - 🔐 Auth Server
  - 📥 Download Server
  - 🔄 Update Server
  - 📊 Telemetry/Analytics
  - 🌐 CDN
  - ☁️ Cloud Server

**How to use:**
1. **RUN the program as administrator!**
2. Open "Network Monitor" tab
3. Select process to monitor
4. Click "Start monitoring"
5. **See all servers it connects to!**

**Perfect for tracking cheat servers!**

## 📦 Installation

### Requirements
- Windows 10/11
- .NET 8.0 Runtime or SDK
- Administrator rights (for Memory Scanner and Network Monitor)

### Build from source

#### Option 1: Using build script (Easiest!)
Double-click `build.bat` or run in CMD:
```cmd
build.bat
```

#### Option 2: Manual build in CMD
```cmd
cd ReverseToolkit
dotnet restore
dotnet build -c Release
```

#### Option 3: Visual Studio
Open `ReverseToolkit.sln` in Visual Studio and press F5

### Run

**IMPORTANT:** Right-click `ReverseToolkit.exe` → **Run as administrator**

## 🎨 Interface

- **Dark theme** (Visual Studio Code style)
- **Clean and intuitive UI**
- **6 powerful tools** in one application
- **Real-time language switching**

## 💡 Quick Tips

### Memory Scanner
- Always start with "Unknown Value" if you don't know the exact value
- Use "Range" to search for values within a range
- Float values may have inaccuracies - use range search

### Network Monitor
- Start BEFORE launching target process
- Use filters to reduce noise
- Pay attention to server types
- **Requires Administrator rights!**

### Pattern Scanner
- Use `?` for wildcards in patterns
- Search for unique byte sequences
- Example patterns:
  - `E8 ? ? ? ?` - CALL instruction
  - `48 8B 05 ? ? ? ?` - MOV RAX, [rel]
  - `FF 25` - JMP [rel]

## 🌍 Language / Язык

The application automatically starts in English.

**To switch to Russian:**
1. Open menu: `Tools` → `Language`
2. The entire interface switches to Russian instantly!

**Чтобы переключить на русский:**
1. Откройте меню: `Tools` → `Language`
2. Весь интерфейс мгновенно переключится на русский!

## 🛡️ Security and Ethics

### Legal applications
- Analyze your own code for vulnerabilities
- Research protection mechanisms to improve them
- Education and training in cybersecurity
- Testing with written permission from owner

### Illegal applications (PROHIBITED)
- Creating cheats for multiplayer games
- Bypassing DRM and license protections
- Hacking programs without permission
- Any actions violating EULA or laws

## 📚 Project Structure

```
Reverse/
├── README.md
├── QUICKSTART.md
├── build.ps1
├── ReverseToolkit.sln
└── ReverseToolkit/
    ├── MainWindow.xaml      # UI with language binding
    ├── MainWindow.xaml.cs   # Logic with localization
    ├── Localization/        # Language system
    │   ├── LocalizationManager.cs    # Language manager
    │   └── LocalizationConverter.cs  # XAML converter
    ├── Core/                # 6 engines
    │   ├── PEAnalyzer.cs
    │   ├── HexEditorEngine.cs
    │   ├── MemoryScanner.cs
    │   ├── PatternScanner.cs
    │   ├── NetworkMonitor.cs
    │   └── DisassemblerEngine.cs
    └── Dialogs/             # Localized dialogs
        ├── InputDialog.xaml
        └── SearchDialog.xaml
```

## 🔧 Technology Stack

- **.NET 8.0** - Core framework
- **WPF** - UI framework with data binding
- **Custom Localization System** - Real-time language switching
- **Built-in Disassembler** - Simplified x86/x64 disassembly
- **Windows API** - Memory & network access (P/Invoke)

## 📞 Contact

For questions or bug reports, create Issues in the project repository.

---

**Remember: use this knowledge for defense, not attack! 🛡️**

**Помните: используйте эти знания для защиты, а не для атаки! 🛡️**
