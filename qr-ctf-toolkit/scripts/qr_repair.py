#!/usr/bin/env python3
"""
QR Code Repair and Enhancement Tool
Author: QR CTF Toolkit
Version: 1.0

Usage: python qr_repair.py <damaged_qr.png> [options]

Provides various image processing techniques to repair damaged QR codes:
- Add quiet zone (white border)
- Fix perspective distortion
- Enhance contrast
- Extract color channels
- Denoise and clean up
"""

import sys
import os
import cv2
import numpy as np
from PIL import Image
from pyzbar import pyzbar

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════╗
║      QR Code Repair Toolkit         ║
║    Image Processing & Enhancement   ║
╚══════════════════════════════════════╝
    """
    print(banner)

def try_scan(image_path):
    """Try to scan QR code from image"""
    try:
        img = Image.open(image_path)
        codes = pyzbar.decode(img)
        if codes:
            return codes[0].data.decode('utf-8', errors='ignore')
    except:
        pass
    return None

def add_quiet_zone(image_path, border_size=30, color='white'):
    """Add white border (quiet zone) to QR code"""
    print(f"\n[*] Adding quiet zone ({border_size}px {color} border)...")

    try:
        img = cv2.imread(image_path)
        if img is None:
            print("[!] Failed to load image")
            return None

        # Determine border color
        if color == 'white':
            border_color = [255, 255, 255]
        else:
            border_color = [0, 0, 0]

        # Add border
        bordered = cv2.copyMakeBorder(img, border_size, border_size,
                                     border_size, border_size,
                                     cv2.BORDER_CONSTANT,
                                     value=border_color)

        output = image_path.replace('.', '_bordered.')
        cv2.imwrite(output, bordered)
        print(f"[+] Saved: {output}")

        # Try to scan
        result = try_scan(output)
        if result:
            print(f"[+] SUCCESS! Decoded: {result}")

        return output

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def fix_perspective(image_path):
    """Attempt to fix perspective distortion"""
    print(f"\n[*] Attempting perspective correction...")

    try:
        img = cv2.imread(image_path)
        if img is None:
            print("[!] Failed to load image")
            return None

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # Apply threshold to get binary image
        _, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)

        # Find contours
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL,
                                       cv2.CHAIN_APPROX_SIMPLE)

        if not contours:
            print("[-] No contours found")
            return None

        # Get largest contour (hopefully the QR code)
        largest = max(contours, key=cv2.contourArea)

        # Get the minimum area rectangle
        rect = cv2.minAreaRect(largest)
        box = cv2.boxPoints(rect)
        box = np.int0(box)

        # Order points for perspective transform
        def order_points(pts):
            rect = np.zeros((4, 2), dtype="float32")
            s = pts.sum(axis=1)
            diff = np.diff(pts, axis=1)
            rect[0] = pts[np.argmin(s)]  # Top-left
            rect[2] = pts[np.argmax(s)]  # Bottom-right
            rect[1] = pts[np.argmin(diff)]  # Top-right
            rect[3] = pts[np.argmax(diff)]  # Bottom-left
            return rect

        src = order_points(box)

        # Define destination points (square)
        size = 500
        dst = np.array([[0, 0], [size, 0], [size, size], [0, size]],
                      dtype=np.float32)

        # Get transformation matrix and apply
        matrix = cv2.getPerspectiveTransform(src, dst)
        result = cv2.warpPerspective(img, matrix, (size, size))

        output = image_path.replace('.', '_perspective.')
        cv2.imwrite(output, result)
        print(f"[+] Saved: {output}")

        # Try to scan
        scan_result = try_scan(output)
        if scan_result:
            print(f"[+] SUCCESS! Decoded: {scan_result}")

        return output

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def enhance_contrast(image_path, method='clahe'):
    """Enhance contrast and clean up image"""
    print(f"\n[*] Enhancing contrast (method: {method})...")

    try:
        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            print("[!] Failed to load image")
            return None

        if method == 'clahe':
            # Apply CLAHE (Contrast Limited Adaptive Histogram Equalization)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
            enhanced = clahe.apply(img)

        elif method == 'histogram':
            # Simple histogram equalization
            enhanced = cv2.equalizeHist(img)

        elif method == 'gamma':
            # Gamma correction
            gamma = 1.5
            enhanced = np.power(img/255.0, gamma) * 255
            enhanced = enhanced.astype(np.uint8)

        else:
            print("[!] Unknown method")
            return None

        # Threshold to pure black and white
        _, binary = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

        output = image_path.replace('.', f'_enhanced_{method}.')
        cv2.imwrite(output, binary)
        print(f"[+] Saved: {output}")

        # Try to scan
        result = try_scan(output)
        if result:
            print(f"[+] SUCCESS! Decoded: {result}")

        return output

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def extract_color_channels(image_path):
    """Extract individual color channels"""
    print(f"\n[*] Extracting color channels...")

    try:
        img = cv2.imread(image_path)
        if img is None:
            print("[!] Failed to load image")
            return None

        b, g, r = cv2.split(img)

        channels = {'blue': b, 'green': g, 'red': r}
        outputs = []

        for name, channel in channels.items():
            output = image_path.replace('.', f'_{name}.')
            cv2.imwrite(output, channel)
            outputs.append(output)
            print(f"[+] Saved {name} channel: {output}")

            # Try to scan
            result = try_scan(output)
            if result:
                print(f"[+] SUCCESS in {name} channel! Decoded: {result}")

        return outputs

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def denoise_image(image_path):
    """Apply denoising filters"""
    print(f"\n[*] Applying denoising filters...")

    try:
        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            print("[!] Failed to load image")
            return None

        # Apply different denoising methods
        methods = [
            ('median', cv2.medianBlur(img, 3)),
            ('gaussian', cv2.GaussianBlur(img, (3,3), 0)),
            ('bilateral', cv2.bilateralFilter(img, 9, 75, 75)),
            ('morphological', cv2.morphologyEx(img, cv2.MORPH_OPEN,
                                              cv2.getStructuringElement(cv2.MORPH_RECT, (3,3))))
        ]

        outputs = []
        for name, denoised in methods:
            # Threshold to binary
            _, binary = cv2.threshold(denoised, 127, 255, cv2.THRESH_BINARY)

            output = image_path.replace('.', f'_denoised_{name}.')
            cv2.imwrite(output, binary)
            outputs.append(output)
            print(f"[+] Saved {name} denoised: {output}")

            # Try to scan
            result = try_scan(output)
            if result:
                print(f"[+] SUCCESS with {name} denoising! Decoded: {result}")

        return outputs

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def invert_colors(image_path):
    """Invert image colors"""
    print(f"\n[*] Inverting colors...")

    try:
        img = cv2.imread(image_path)
        if img is None:
            print("[!] Failed to load image")
            return None

        inverted = cv2.bitwise_not(img)

        output = image_path.replace('.', '_inverted.')
        cv2.imwrite(output, inverted)
        print(f"[+] Saved: {output}")

        # Try to scan
        result = try_scan(output)
        if result:
            print(f"[+] SUCCESS! Decoded: {result}")

        return output

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def resize_image(image_path, size=500):
    """Resize image to standard size"""
    print(f"\n[*] Resizing to {size}x{size}...")

    try:
        img = cv2.imread(image_path)
        if img is None:
            print("[!] Failed to load image")
            return None

        resized = cv2.resize(img, (size, size))

        output = image_path.replace('.', f'_resized{size}.')
        cv2.imwrite(output, resized)
        print(f"[+] Saved: {output}")

        # Try to scan
        result = try_scan(output)
        if result:
            print(f"[+] SUCCESS! Decoded: {result}")

        return output

    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def auto_repair_pipeline(image_path):
    """Run all repair methods automatically"""
    print("\n" + "=" * 50)
    print("[*] RUNNING AUTO-REPAIR PIPELINE")
    print("=" * 50)

    repairs = [
        ('Adding quiet zone', lambda: add_quiet_zone(image_path)),
        ('Inverting colors', lambda: invert_colors(image_path)),
        ('Enhancing contrast (CLAHE)', lambda: enhance_contrast(image_path, 'clahe')),
        ('Denoising', lambda: denoise_image(image_path)),
        ('Perspective correction', lambda: fix_perspective(image_path)),
        ('Color channel extraction', lambda: extract_color_channels(image_path)),
        ('Resizing', lambda: resize_image(image_path))
    ]

    successful = []
    failed = []

    for name, repair_func in repairs:
        print(f"\n{'='*50}")
        print(f"[*] Trying: {name}")
        print('='*50)

        try:
            result = repair_func()
            if result:
                # Check if any repair was successful (detected QR)
                if isinstance(result, list):
                    for r in result:
                        if try_scan(r):
                            successful.append(name)
                            break
                elif try_scan(result):
                    successful.append(name)
                else:
                    failed.append(name)
        except Exception as e:
            print(f"[!] Failed: {e}")
            failed.append(name)

    # Print summary
    print("\n" + "=" * 50)
    print("[*] AUTO-REPAIR SUMMARY")
    print("=" * 50)

    if successful:
        print("\n[+] Successful repairs:")
        for s in successful:
            print(f"    - {s}")
    else:
        print("\n[-] No successful repairs")

    if failed:
        print("\n[-] Failed repairs:")
        for f in failed:
            print(f"    - {f}")

    print("\n[*] Recommendation:")
    if successful:
        print("    Use the successful repair method's output file")
    else:
        print("    Consider manual repair in GIMP or QRazyBox")
        print("    The QR might be too damaged for automated repair")

def print_usage():
    """Print usage information"""
    print("\nUsage: python qr_repair.py <damaged_qr.png> [options]")
    print("\nOptions:")
    print("  -a, --auto          Run all repair methods automatically")
    print("  -q, --quiet-zone    Add quiet zone (white border)")
    print("  -p, --perspective   Fix perspective distortion")
    print("  -c, --contrast      Enhance contrast")
    print("  -d, --denoise       Apply denoising")
    print("  -i, --invert        Invert colors")
    print("  -x, --extract       Extract color channels")
    print("  -r, --resize        Resize to standard size")
    print("\nExamples:")
    print("  python qr_repair.py damaged.png --auto")
    print("  python qr_repair.py skewed.png --perspective")
    print("  python qr_repair.py noisy.png --denoise --contrast")
    print("\nThe tool will attempt to scan repaired images and")
    print("report if decoding is successful.")

def main():
    """Main function"""
    print_banner()

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    image_path = sys.argv[1]

    if not os.path.exists(image_path):
        print(f"[!] Error: File not found: {image_path}")
        sys.exit(1)

    # Check initial scan
    print(f"\n[*] Testing original image: {image_path}")
    initial_result = try_scan(image_path)
    if initial_result:
        print(f"[+] Already scannable! Decoded: {initial_result}")
        print("[*] No repair needed")
        sys.exit(0)
    else:
        print("[-] Cannot scan original image, repairs needed")

    # Parse options
    if len(sys.argv) > 2:
        options = sys.argv[2:]

        if '-a' in options or '--auto' in options:
            auto_repair_pipeline(image_path)
        else:
            if '-q' in options or '--quiet-zone' in options:
                add_quiet_zone(image_path)
            if '-p' in options or '--perspective' in options:
                fix_perspective(image_path)
            if '-c' in options or '--contrast' in options:
                enhance_contrast(image_path)
            if '-d' in options or '--denoise' in options:
                denoise_image(image_path)
            if '-i' in options or '--invert' in options:
                invert_colors(image_path)
            if '-x' in options or '--extract' in options:
                extract_color_channels(image_path)
            if '-r' in options or '--resize' in options:
                resize_image(image_path)
    else:
        print("\n[*] No options specified, running auto-repair pipeline")
        auto_repair_pipeline(image_path)

    print("\n[*] Repair process complete!")
    print("[*] Check the generated files for successful scans")

if __name__ == "__main__":
    main()