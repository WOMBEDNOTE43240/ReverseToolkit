# 🚀 Quick Start Guide

## Build & Run

### 1. Install .NET 8.0 SDK
Download from: https://dotnet.microsoft.com/download/dotnet/8.0

### 2. Build the project
```powershell
cd "c:\Users\SystemX\Desktop\Test Programs\Reverse"
.\build.ps1
```

Or manually:
```powershell
cd ReverseToolkit
dotnet restore
dotnet build -c Release
```

### 3. Run as Administrator
**IMPORTANT:** Right-click `ReverseToolkit.exe` → Run as administrator

The executable will be at:
`ReverseToolkit\bin\Release\net8.0-windows\ReverseToolkit.exe`

## Features Overview

### 📋 PE Analyzer
- Analyze EXE/DLL file structure
- View imports (what functions the program uses)
- View exports (what functions it provides)
- Support for x86 and x64

### 🔢 Hex Editor
- View and edit binary files
- Search for byte patterns
- Auto-detect file types

### 🧠 Memory Scanner
- Scan running process memory
- Find and modify values
- Freeze values in real-time
- **Requires Administrator rights**

### 🔍 Pattern Scanner
- Search byte patterns with wildcards (?)
- Example: `E8 ? ? ? ?` finds all CALL instructions
- Works in files and process memory

### ⚙️ Disassembler
- Disassemble x86/x64 machine code
- View assembly instructions
- Function analysis

### 🌐 Network Monitor ⭐ KEY FEATURE
- **Track ALL network connections of a process**
- Automatically resolve DNS names
- Identify server types:
  - Game Server
  - Auth Server
  - Download Server
  - Update Server
  - CDN
  - And more...
- **Perfect for tracking cheat servers!**
- **Requires Administrator rights**

## Quick Examples

### Example 1: Analyze suspicious EXE
1. Open PE Analyzer tab
2. Load file
3. Check Imports tab → look for suspicious DLLs
4. Check Sections tab → look for unusual sections

### Example 2: Track cheat network activity
1. **Run as Administrator**
2. Open Network Monitor tab
3. Select cheat process
4. Click "Start monitoring"
5. **See all servers it connects to!**

### Example 3: Find game value in memory
1. **Run as Administrator**
2. Open Memory Scanner
3. Select game process
4. Enter known value (e.g., health = 100)
5. First Scan
6. Change value in game
7. Next Scan with new value
8. Repeat until 1-10 results
9. Modify or Freeze value

## ⚠️ LEGAL USE ONLY

This tool is for:
- ✅ Security research
- ✅ Anti-cheat development
- ✅ Education
- ❌ **NOT** for creating game cheats

## Troubleshooting

**Memory Scanner/Network Monitor not working?**
→ Run as Administrator!

**Antivirus blocking?**
→ Add to exceptions (false positive for reverse engineering tools)

**Build errors?**
→ Run `dotnet restore` then `dotnet build`

## More Information

- **Full documentation:** README.md
- **Examples:** EXAMPLES.md (coming soon)
- **Installation help:** Check if .NET 8.0 SDK is installed

---

**Happy analyzing! 🔧**
