# Complete QR Code CTF Challenge Workflow Guide for Windows

## Table of Contents
1. [Quick Start Checklist](#quick-start-checklist)
2. [Tool Installation Guide](#tool-installation-guide)
3. [Challenge Type Decision Tree](#challenge-type-decision-tree)
4. [Python Automation Scripts](#python-automation-scripts)
5. [PowerShell Commands](#powershell-commands)
6. [Recovery Techniques](#recovery-techniques)
7. [Quick Reference Cards](#quick-reference-cards)
8. [Common Scenarios and Solutions](#common-scenarios-and-solutions)

---

## Quick Start Checklist

### Immediate Actions for Any QR Challenge:
1. ☐ Create working directory and keep original file untouched
2. ☐ Try basic scan with multiple tools (zbarimg, mobile app)
3. ☐ Check file metadata (exiftool, pngcheck)
4. ☐ If scan fails, check for steganography
5. ☐ If damaged, attempt reconstruction in QRazyBox
6. ☐ Decode any encoded payloads with CyberChef

---

## Tool Installation Guide

### Essential Tools Setup (Windows)

#### 1. Python Environment
```powershell
# Download Python from python.org (check "Add to PATH")
# Install required libraries
pip install pyzbar pillow opencv-python numpy qrcode[pil] requests
pip install pyzbar[scripts]  # Includes zbar DLLs
```

#### 2. Core QR Decoders
```powershell
# ZBar (Method 1: via pip)
pip install pyzbar

# ZBar (Method 2: Windows binary)
# Download from: https://sourceforge.net/projects/zbar/
# Add to PATH after installation

# ZXing-C++
# Download from: https://github.com/zxing-cpp/zxing-cpp/releases
# Look for Windows binaries (ZXingReader.exe)
```

#### 3. Image Manipulation Tools
```powershell
# GIMP
winget install GIMP.GIMP
# OR download from: https://www.gimp.org/downloads/

# ImageMagick
winget install ImageMagick.ImageMagick
# OR download from: https://imagemagick.org/script/download.php
```

#### 4. Forensic Tools
```powershell
# HxD Hex Editor
# Download from: https://mh-nexus.de/en/hxd/
# Portable version available

# ExifTool
# Download from: https://exiftool.org/
# Extract and add to PATH

# pngcheck
# Download from: http://www.libpng.org/pub/png/apps/pngcheck.html
```

#### 5. Steganography Tools
```powershell
# StegSolve (requires Java)
# 1. Install Java from: https://www.oracle.com/java/technologies/downloads/
# 2. Download StegSolve.jar from: https://github.com/zer00d4y/stegsolve
# 3. Run with: java -jar StegSolve.jar

# zsteg (Ruby-based)
# 1. Install Ruby+DevKit from: https://rubyinstaller.org/
# 2. Install zsteg:
gem install zsteg

# Binwalk
pip install binwalk
```

#### 6. Web Tools (No Installation)
- **QRazyBox**: https://merri.cx/qrazybox/
- **CyberChef**: https://gchq.github.io/CyberChef/ (download for offline use)

---

## Challenge Type Decision Tree

```
START: Received QR Code Challenge
│
├─[Can it scan?]─── YES ──→ [Decode Payload]
│                             │
│                             ├─ Plain text? → Check for flag
│                             ├─ Base64? → Decode
│                             ├─ Hex? → Convert
│                             ├─ URL? → Visit
│                             └─ Encrypted? → CyberChef
│
├─[Can it scan?]─── NO ───→ [File Analysis]
│                             │
│                             ├─[Metadata suspicious?] → ExifTool
│                             ├─[PNG/BMP?] → zsteg/StegSolve
│                             ├─[Embedded files?] → Binwalk
│                             └─[Continue to repair]
│                             │
│                             ↓
│                         [Visual Inspection]
│                             │
│                             ├─[Missing corners?] → GIMP repair
│                             ├─[Color issues?] → Channel separation
│                             ├─[Distorted?] → Perspective correction
│                             └─[Damaged data?] → QRazyBox
│
└─[Special Format?]
    ├─ GIF/Video → Extract frames
    ├─ Multiple QRs → XOR/Concatenate
    └─ PDF → Extract images first
```

---

## Python Automation Scripts

### Main Scripts Overview
- **qr_analyzer.py**: Comprehensive automated analysis
- **frame_extractor.py**: Extract QR codes from animated GIFs
- **qr_repair.py**: Image preprocessing and repair utilities
- **xor_qr.py**: XOR multiple QR codes to reveal hidden data

See the `scripts/` directory for full implementations.

---

## PowerShell Commands

### Quick Setup Script
Run `powershell\setup.ps1` to automatically install all required tools and dependencies.

### Quick Scan Script
```powershell
.\powershell\quick_scan.ps1 -ImagePath "challenge.png"
```

### Batch Processing
```powershell
.\powershell\batch_qr.ps1 -Directory "C:\ctf\qr_challenges"
```

---

## Recovery Techniques

### 1. Manual QR Reconstruction in GIMP

**For Missing Finder Patterns:**
1. Open damaged QR in GIMP
2. View → Show Grid (set to QR module size)
3. Select intact finder pattern with Rectangle Select
4. Edit → Copy, then paste and move to damaged corner
5. Use Pencil tool (1px) to fix timing patterns

**For Data Area Damage:**
1. Create new layer for repairs
2. Use Pencil tool to fill damaged modules
3. Gray = unknown (for QRazyBox)
4. Export as PNG for processing

### 2. QRazyBox Recovery Process

1. **Upload Image**: Load damaged QR
2. **Set Version**: Count modules (21×21 = v1, 25×25 = v2, etc.)
3. **Format Info Recovery**:
   - Tools → Format Info Pattern
   - Try all 32 combinations (4 ECL × 8 masks)
4. **Data Extraction**:
   - Tools → Extract QR Information
   - Note "missing bytes" count
5. **Reed-Solomon Recovery**:
   - If missing bytes ≤ error correction capacity
   - Tools → Reed-Solomon Decoder
   - Recovers data mathematically

### 3. Error Correction Levels

| Level | Code | Recovery % | Codewords |
|-------|------|-----------|-----------|
| L     | 01   | ~7%       | Low       |
| M     | 00   | ~15%      | Medium    |
| Q     | 11   | ~25%      | Quartile  |
| H     | 10   | ~30%      | High      |

### 4. QR Code Structure

```
┌─────────────────────────┐
│ ███████ ░░░░░░░ ███████ │  <- Finder patterns (corners)
│ █     █ ░DATA░░ █     █ │
│ █ ███ █ ░AREA░░ █ ███ █ │
│ █ ███ █ ░░░░░░░ █ ███ █ │
│ █ ███ █ ████████ █ ███ █ │  <- Timing patterns (lines)
│ █     █ █      █ █     █ │
│ ███████ █ █ █ █ ███████ │
│ ░░░░░░░ ████████ ░░░░░░░ │  <- Format info (around finders)
│ DATA░░░ █      █ ░░DATA │
│ AREA░░░ ████████ ░░AREA │
│ ░░░░░░░ ░░░░░░░░ ░░░░░░░ │
│ ███████ ░░░░░░░░ ░░░░░░░ │
│ █     █ ░░DATA░░ ░DATA░░ │
│ █ ███ █ ░░AREA░░ ░AREA░░ │
│ █ ███ █ ░░░░░░░░ ░░░░░░░ │
│ █ ███ █ ░░░░░░░░ ███ ███ │  <- Alignment pattern (v2+)
│ █     █ ░░░░░░░░ ███ ███ │
│ ███████ ░░░░░░░░ ░░░░░░░ │
└─────────────────────────┘
```

---

## Quick Reference Cards

### Common CTF Patterns

| Symptom | Likely Issue | Solution |
|---------|-------------|----------|
| Scans but gibberish | Encoded payload | Try Base64, ROT13, hex |
| Won't scan at all | Missing quiet zone | Add white border |
| Partially damaged | Reed-Solomon possible | Use QRazyBox |
| Multiple QR images | XOR or concatenate | Use xor_qr.py |
| Animated GIF | Frame-based data | Extract frames |
| Looks perfect, won't scan | Inverted colors | Negate image |
| Blurry/distorted | Perspective issue | OpenCV correction |
| PNG with hints | Steganography | StegSolve, zsteg |

### Command Cheatsheet

```bash
# Quick scan
zbarimg challenge.png

# Extract GIF frames
ffmpeg -i challenge.gif frame_%04d.png

# Check PNG chunks
pngcheck -v challenge.png

# Metadata inspection
exiftool challenge.png

# Steganography (PNG/BMP)
zsteg -a challenge.png

# Add white border (ImageMagick)
magick challenge.png -bordercolor white -border 30 fixed.png

# Invert colors
magick challenge.png -negate inverted.png

# Extract color channels
magick challenge.png -separate channel_%d.png

# Check for appended data
xxd challenge.png | tail -20

# Strings extraction
strings challenge.png | grep -i flag
```

### Decoding Pipeline

```
Raw QR Data
    ↓
[Check if Base64] → base64 -d
    ↓
[Check if Hex] → xxd -r -p
    ↓
[Check if ROT13] → tr 'A-Za-z' 'N-ZA-Mn-za-m'
    ↓
[Check if URL encoded] → python -c "import urllib.parse; ..."
    ↓
[Check if compressed] → gunzip / unzip
    ↓
FLAG
```

---

## Common Scenarios and Solutions

### Scenario 1: Clean QR, Encoded Output
```bash
# Scan returns: SGVsbG8gV29ybGQh
zbarimg qr.png | base64 -d
# Result: Hello World!
```

### Scenario 2: Damaged QR Code
1. Open in GIMP, fix obvious damage
2. Upload to QRazyBox
3. Brute force format info
4. Run Reed-Solomon decoder

### Scenario 3: Hidden in PNG
```bash
# Check all planes
zsteg -a suspicious.png
# Found flag in b1,rgb,lsb
```

### Scenario 4: Animated GIF
```python
# Extract and concatenate
python scripts/frame_extractor.py animated.gif
# Each frame = one character
```

### Scenario 5: XOR Challenge
```python
# Two noise images
python scripts/xor_qr.py noise1.png noise2.png
# Creates readable QR
```

### Scenario 6: PDF Container
```bash
# Extract images first
pdfimages -all challenge.pdf output
# Then scan extracted images
```

---

## Advanced Tips

1. **Always Keep Originals**: Work on copies
2. **Document Everything**: Screenshot successful settings
3. **Try Multiple Tools**: Different libraries catch different things
4. **Think in Layers**: QR → Encoding → Encryption → Flag
5. **Check CTF Writeups**: Similar challenges often reuse techniques
6. **Automate Common Tasks**: Use the Python scripts
7. **Learn QR Structure**: Understanding helps manual repair

---

## Challenge Archetypes

### 1. Standard Scan (Layered Encoding)
- QR scans successfully but data is encoded
- Apply multiple decoding layers (Base64, ROT13, hex)
- Use CyberChef for complex chains

### 2. Broken Code (Reconstruction)
- QR is damaged and won't scan
- Use GIMP for visual repairs
- QRazyBox for Reed-Solomon recovery
- Manual bit manipulation if needed

### 3. Moving Picture (Animated Sequences)
- Data split across multiple frames
- Extract frames with FFmpeg or Python
- Decode each frame and concatenate
- Look for timing-based patterns

### 4. Hidden Message (Steganography)
- QR is a decoy or contains hints
- Check LSB with zsteg
- Analyze bit planes with StegSolve
- Look for appended data in hex

### 5. Esoteric Puzzle (Advanced Logic)
- Multiple QRs requiring operations
- XOR images together
- Color channel separation
- Custom encoding schemes

---

## QR Code Specifications

### Version and Size
- Version 1: 21×21 modules
- Version 2: 25×25 modules
- Version 3: 29×29 modules
- Version N: (4N + 17) × (4N + 17) modules

### Data Capacity (Version 1, ECL-L)
- Numeric: 41 characters
- Alphanumeric: 25 characters
- Byte: 17 characters
- Kanji: 10 characters

### Mask Patterns (0-7)
- Pattern 0: (row + column) mod 2 == 0
- Pattern 1: row mod 2 == 0
- Pattern 2: column mod 3 == 0
- Pattern 3: (row + column) mod 3 == 0
- Pattern 4: ((row/2) + (column/3)) mod 2 == 0
- Pattern 5: ((row×column) mod 2) + ((row×column) mod 3) == 0
- Pattern 6: (((row×column) mod 2) + ((row×column) mod 3)) mod 2 == 0
- Pattern 7: (((row+column) mod 2) + ((row×column) mod 3)) mod 2 == 0

---

## Resources and References

- QR Code Specification: ISO/IEC 18004
- QRazyBox: https://merri.cx/qrazybox/
- CyberChef: https://gchq.github.io/CyberChef/
- StegSolve: https://github.com/zer00d4y/stegsolve
- CTFtime Writeups: https://ctftime.org/writeups
- QR Code Tutorial: https://www.thonky.com/qr-code-tutorial/

---

## Troubleshooting

**Problem**: "Module pyzbar not found"
- Solution: `pip install pyzbar[scripts]`

**Problem**: "zbarimg command not found"
- Solution: Install ZBar or use pyzbar Python module

**Problem**: "Java not found" (for StegSolve)
- Solution: Install Java JRE from Oracle

**Problem**: QRazyBox won't load image
- Solution: Convert to PNG, ensure proper format

**Problem**: Can't install Ruby gems (Windows)
- Solution: Use RubyInstaller with DevKit

**Problem**: OpenCV import error
- Solution: `pip install opencv-python-headless`

**Problem**: ImageMagick not recognized
- Solution: Add ImageMagick to system PATH

---

*Last Updated: 2024*
*Version: 1.0*
*Author: QR CTF Toolkit*