#!/usr/bin/env python3
"""
Comprehensive QR Code CTF Analyzer
Author: QR CTF Toolkit
Version: 1.0

Usage: python qr_analyzer.py <image_file>

This script performs multiple analysis techniques:
- Basic QR scanning
- Enhanced preprocessing (threshold, adaptive, blur, invert)
- Multi-stage decoding (Base64, ROT13, hex, URL)
- Steganography detection
- File forensics
"""

import os
import sys
import subprocess
import base64
import binascii
import codecs
from PIL import Image
from pyzbar import pyzbar
import cv2
import numpy as np
from urllib.parse import unquote

class QRCTFAnalyzer:
    def __init__(self, image_path):
        self.image_path = image_path
        self.results = {}
        self.flag_found = False

    def print_banner(self):
        """Print analysis banner"""
        banner = """
╔══════════════════════════════════════╗
║     QR Code CTF Analyzer v1.0        ║
║     Comprehensive Analysis Tool      ║
╚══════════════════════════════════════╝
        """
        print(banner)

    def basic_scan(self):
        """Attempt basic QR code scanning"""
        print("\n[*] Stage 1: Basic QR Scanning...")
        print("-" * 40)

        try:
            img = Image.open(self.image_path)
            codes = pyzbar.decode(img)

            if codes:
                for i, code in enumerate(codes):
                    try:
                        data = code.data.decode('utf-8')
                    except:
                        data = code.data.decode('utf-8', errors='ignore')

                    self.results[f'basic_scan_{i}'] = {
                        'data': data,
                        'type': code.type,
                        'rect': code.rect,
                        'polygon': code.polygon
                    }

                    print(f"[+] QR Code {i+1} found!")
                    print(f"    Type: {code.type}")
                    print(f"    Data: {data}")
                    print(f"    Position: {code.rect}")

                    # Check for flag patterns
                    self.check_for_flag(data, "basic_scan")

                return True
            else:
                print("[-] No QR code found with basic scan")
                return False

        except Exception as e:
            print(f"[!] Error in basic scan: {e}")
            self.results['basic_scan_error'] = str(e)
            return False

    def enhanced_preprocessing(self):
        """Apply various preprocessing techniques"""
        print("\n[*] Stage 2: Enhanced Preprocessing...")
        print("-" * 40)

        try:
            img = cv2.imread(self.image_path, cv2.IMREAD_GRAYSCALE)

            if img is None:
                print("[!] Failed to load image with OpenCV")
                return False

            techniques = [
                ('binary_threshold', cv2.threshold(img, 127, 255, cv2.THRESH_BINARY)[1]),
                ('otsu_threshold', cv2.threshold(img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]),
                ('adaptive_gaussian', cv2.adaptiveThreshold(img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                                          cv2.THRESH_BINARY, 11, 2)),
                ('adaptive_mean', cv2.adaptiveThreshold(img, 255, cv2.ADAPTIVE_THRESH_MEAN_C,
                                                       cv2.THRESH_BINARY, 11, 2)),
                ('blur_threshold', cv2.threshold(cv2.GaussianBlur(img, (5,5), 0), 127, 255,
                                                cv2.THRESH_BINARY)[1]),
                ('median_blur', cv2.medianBlur(img, 5)),
                ('inverted', cv2.bitwise_not(img)),
                ('inverted_otsu', cv2.bitwise_not(cv2.threshold(img, 0, 255,
                                                                cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]))
            ]

            for name, processed_img in techniques:
                print(f"  Trying {name}...", end="")

                # Convert to PIL Image for pyzbar
                pil_img = Image.fromarray(processed_img)
                codes = pyzbar.decode(pil_img)

                if codes:
                    data = codes[0].data.decode('utf-8', errors='ignore')
                    self.results[f'preprocessing_{name}'] = {
                        'data': data,
                        'technique': name
                    }
                    print(f" [+] SUCCESS!")
                    print(f"      Data: {data}")
                    self.check_for_flag(data, f"preprocessing_{name}")
                    return True
                else:
                    print(" [-] No QR found")

            print("[-] All preprocessing attempts failed")
            return False

        except Exception as e:
            print(f"[!] Error in preprocessing: {e}")
            return False

    def check_steganography(self):
        """Run steganography and forensic checks"""
        print("\n[*] Stage 3: Steganography & Forensics...")
        print("-" * 40)

        # Check file size
        file_size = os.path.getsize(self.image_path)
        print(f"[i] File size: {file_size:,} bytes")

        # Try strings command
        print("\n[*] Checking for embedded strings...")
        try:
            # For Windows, use a Python alternative to strings
            with open(self.image_path, 'rb') as f:
                data = f.read()

            # Look for printable ASCII strings
            import string
            printable = set(string.printable.encode())
            min_length = 6
            current_string = b""
            strings_found = []

            for byte in data:
                if bytes([byte]) in printable or chr(byte) in string.printable:
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        try:
                            decoded = current_string.decode('ascii', errors='ignore')
                            strings_found.append(decoded)
                        except:
                            pass
                    current_string = b""

            # Check for interesting strings
            interesting_patterns = ['flag', 'ctf', 'FLAG', 'CTF', 'key', 'secret', 'password']
            for s in strings_found:
                for pattern in interesting_patterns:
                    if pattern in s:
                        print(f"[+] Found interesting string: {s}")
                        self.results['strings'] = s
                        self.check_for_flag(s, "strings")

        except Exception as e:
            print(f"[!] String extraction error: {e}")

        # Check for data after PNG IEND chunk
        print("\n[*] Checking for appended data...")
        try:
            with open(self.image_path, 'rb') as f:
                data = f.read()

            # Look for PNG IEND chunk
            if b'IEND' in data:
                iend_pos = data.find(b'IEND\xae\x42\x60\x82')
                if iend_pos != -1:
                    after_iend = data[iend_pos + 8:]
                    if len(after_iend) > 0:
                        print(f"[+] Found {len(after_iend)} bytes after PNG IEND chunk!")
                        self.results['appended_data'] = f"{len(after_iend)} bytes found"

                        # Try to decode as text
                        try:
                            text = after_iend.decode('utf-8', errors='ignore')
                            if text.strip():
                                print(f"[+] Appended text: {text[:100]}...")
                                self.check_for_flag(text, "appended_data")
                        except:
                            pass

            # Look for JPEG EOI marker
            if b'\xff\xd9' in data:
                eoi_pos = data.rfind(b'\xff\xd9')
                after_eoi = data[eoi_pos + 2:]
                if len(after_eoi) > 0:
                    print(f"[+] Found {len(after_eoi)} bytes after JPEG EOI marker!")
                    self.results['jpeg_appended'] = f"{len(after_eoi)} bytes found"

        except Exception as e:
            print(f"[!] File structure check error: {e}")

        # Check for file signatures within the image
        print("\n[*] Checking for embedded file signatures...")
        signatures = {
            b'PK\x03\x04': 'ZIP archive',
            b'Rar!': 'RAR archive',
            b'\x89PNG': 'PNG image',
            b'\xff\xd8\xff': 'JPEG image',
            b'GIF87a': 'GIF image',
            b'GIF89a': 'GIF image',
            b'%PDF': 'PDF document',
            b'7z\xbc\xaf': '7-Zip archive'
        }

        try:
            with open(self.image_path, 'rb') as f:
                data = f.read()

            for sig, desc in signatures.items():
                if sig in data[100:]:  # Skip the first 100 bytes to avoid the main file signature
                    pos = data.find(sig, 100)
                    print(f"[+] Found {desc} signature at offset {pos}")
                    self.results[f'embedded_{desc}'] = f"At offset {pos}"

        except Exception as e:
            print(f"[!] Signature check error: {e}")

    def multi_stage_decode(self, content):
        """Apply multiple decoding schemes"""
        print("\n[*] Stage 4: Multi-Stage Payload Decoding...")
        print("-" * 40)

        if not content:
            print("[-] No content to decode")
            return content

        current = content
        stages = []

        # Try Base64
        print("  Trying Base64...", end="")
        try:
            # Check if it looks like Base64
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in current.strip()):
                # Pad if necessary
                padding = 4 - (len(current.strip()) % 4)
                if padding != 4:
                    current = current.strip() + ('=' * padding)

                decoded = base64.b64decode(current).decode('utf-8', errors='ignore')
                if decoded and decoded != current and len(decoded) > 0:
                    stages.append('base64')
                    current = decoded
                    print(f" [+] Success")
                    print(f"      Result: {current[:100]}...")
                else:
                    print(" [-] Failed")
            else:
                print(" [-] Not Base64")
        except Exception as e:
            print(f" [-] Failed: {e}")

        # Try ROT13
        print("  Trying ROT13...", end="")
        try:
            rot13 = codecs.decode(current, 'rot_13')
            if 'flag' in rot13.lower() or 'ctf' in rot13.lower():
                stages.append('rot13')
                current = rot13
                print(f" [+] Success")
                print(f"      Result: {current[:100]}...")
            else:
                print(" [-] No flag pattern found")
        except:
            print(" [-] Failed")

        # Try Hex
        print("  Trying Hex...", end="")
        try:
            # Remove spaces and check if it's valid hex
            hex_test = current.replace(' ', '').replace('\n', '')
            if all(c in '0123456789abcdefABCDEF' for c in hex_test) and len(hex_test) % 2 == 0:
                hex_decoded = bytes.fromhex(hex_test).decode('utf-8', errors='ignore')
                if hex_decoded and hex_decoded != current:
                    stages.append('hex')
                    current = hex_decoded
                    print(f" [+] Success")
                    print(f"      Result: {current[:100]}...")
                else:
                    print(" [-] Failed")
            else:
                print(" [-] Not valid hex")
        except:
            print(" [-] Failed")

        # Try URL decode
        print("  Trying URL decode...", end="")
        if '%' in current:
            url_decoded = unquote(current)
            if url_decoded != current:
                stages.append('url')
                current = url_decoded
                print(f" [+] Success")
                print(f"      Result: {current[:100]}...")
            else:
                print(" [-] No change")
        else:
            print(" [-] No URL encoding detected")

        # Try reverse
        print("  Trying Reverse...", end="")
        reversed_str = current[::-1]
        if 'flag' in reversed_str.lower() or 'ctf' in reversed_str.lower():
            stages.append('reverse')
            current = reversed_str
            print(f" [+] Success")
            print(f"      Result: {current[:100]}...")
        else:
            print(" [-] No flag pattern found")

        self.results['multi_decode'] = {
            'final': current,
            'stages': stages,
            'transformations': len(stages)
        }

        self.check_for_flag(current, "multi_decode")

        return current

    def check_for_flag(self, text, source):
        """Check if text contains flag pattern"""
        if not text:
            return

        flag_patterns = [
            'flag{', 'FLAG{', 'ctf{', 'CTF{',
            'flag[', 'FLAG[', 'ctf[', 'CTF[',
            'flag:', 'FLAG:', 'ctf:', 'CTF:'
        ]

        for pattern in flag_patterns:
            if pattern in text:
                print(f"\n[!!!] POTENTIAL FLAG FOUND in {source}!")
                print(f"      Pattern: {pattern}")

                # Try to extract the flag
                import re
                flag_regex = [
                    r'(?i)(flag|ctf)\{[^}]+\}',
                    r'(?i)(flag|ctf)\[[^\]]+\]',
                    r'(?i)(flag|ctf):[^\s]+',
                    r'(?i)(flag|ctf)_[^\s]+'
                ]

                for regex in flag_regex:
                    matches = re.findall(regex, text)
                    if matches:
                        for match in matches:
                            if isinstance(match, tuple):
                                match = ''.join(match)
                            print(f"      Extracted: {match}")
                            self.flag_found = True
                            self.results['flag'] = match

                return True

        return False

    def save_report(self):
        """Save analysis report to file"""
        report_name = self.image_path.replace('.', '_') + '_report.txt'

        with open(report_name, 'w') as f:
            f.write("QR Code CTF Analysis Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Flag Found: {self.flag_found}\n\n")

            for key, value in self.results.items():
                f.write(f"\n[{key}]\n")
                if isinstance(value, dict):
                    for k, v in value.items():
                        f.write(f"  {k}: {v}\n")
                else:
                    f.write(f"  {value}\n")

        print(f"\n[*] Report saved to: {report_name}")

    def run_analysis(self):
        """Execute complete analysis workflow"""
        self.print_banner()
        print(f"\n[*] Target: {self.image_path}")
        print("=" * 50)

        # Stage 1: Basic scan
        basic_success = self.basic_scan()

        # Stage 2: Enhanced preprocessing (if basic scan failed)
        if not basic_success:
            preprocessing_success = self.enhanced_preprocessing()

        # Stage 3: Always check steganography
        self.check_steganography()

        # Stage 4: Decode any found content
        for key, value in self.results.items():
            if isinstance(value, dict) and 'data' in value:
                self.multi_stage_decode(value['data'])

        # Print summary
        print("\n" + "=" * 50)
        print("[*] ANALYSIS SUMMARY")
        print("=" * 50)

        if self.flag_found:
            print("\n[+] FLAG FOUND!")
            if 'flag' in self.results:
                print(f"    {self.results['flag']}")
        else:
            print("\n[-] No flag found (yet)")
            print("    Suggestions:")
            print("    - Try manual analysis with GIMP")
            print("    - Use QRazyBox for damaged codes")
            print("    - Check with StegSolve for visual stego")
            print("    - Try zsteg for LSB steganography")

        print(f"\n[*] Total findings: {len(self.results)}")

        # Save report
        self.save_report()

def print_usage():
    """Print usage information"""
    print("Usage: python qr_analyzer.py <image_path>")
    print("\nExample:")
    print("  python qr_analyzer.py challenge.png")
    print("\nSupported formats: PNG, JPG, GIF, BMP")
    print("\nFeatures:")
    print("  - Multiple QR scanning techniques")
    print("  - Image preprocessing (8 methods)")
    print("  - Steganography detection")
    print("  - Multi-stage payload decoding")
    print("  - Automatic flag extraction")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_usage()
        sys.exit(1)

    image_path = sys.argv[1]

    if not os.path.exists(image_path):
        print(f"[!] Error: File not found: {image_path}")
        sys.exit(1)

    analyzer = QRCTFAnalyzer(image_path)
    analyzer.run_analysis()