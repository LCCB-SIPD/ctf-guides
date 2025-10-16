#!/usr/bin/env python3
"""
XOR QR Code Tool
Author: QR CTF Toolkit
Version: 1.0

Usage: python xor_qr.py qr1.png qr2.png [qr3.png ...]

Performs XOR operations on multiple QR code images to reveal hidden codes.
Common in CTF challenges where multiple "noise" images combine to form the real QR.
"""

import sys
import os
import numpy as np
from PIL import Image
from pyzbar import pyzbar
import cv2

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════╗
║         XOR QR Code Tool            ║
║    Multi-Image XOR Operations       ║
╚══════════════════════════════════════╝
    """
    print(banner)

def try_scan(image_array):
    """Try to scan QR code from numpy array"""
    try:
        # Convert numpy array to PIL Image
        img = Image.fromarray(image_array.astype(np.uint8))
        codes = pyzbar.decode(img)
        if codes:
            return codes[0].data.decode('utf-8', errors='ignore')
    except:
        pass
    return None

def xor_images(image_paths, save_intermediate=False):
    """XOR multiple images together"""
    print(f"\n[*] XORing {len(image_paths)} images...")
    print("-" * 50)

    # Load and validate images
    images = []
    shapes = []

    for i, path in enumerate(image_paths):
        print(f"  Loading: {path}")
        try:
            # Load as grayscale
            img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
            if img is None:
                print(f"[!] Failed to load: {path}")
                return None

            images.append(img)
            shapes.append(img.shape)
            print(f"    Size: {img.shape[0]}x{img.shape[1]}")

        except Exception as e:
            print(f"[!] Error loading {path}: {e}")
            return None

    # Check if all images have the same dimensions
    if len(set(shapes)) > 1:
        print("\n[!] Warning: Images have different sizes!")
        print("    Resizing all to the smallest dimensions...")

        # Find minimum dimensions
        min_height = min(s[0] for s in shapes)
        min_width = min(s[1] for s in shapes)

        # Resize all images
        for i in range(len(images)):
            if images[i].shape != (min_height, min_width):
                images[i] = cv2.resize(images[i], (min_width, min_height))

    print(f"\n[*] Performing XOR operations...")

    # Start with the first image
    result = images[0].copy()

    # Convert to binary (0 or 255)
    result = ((result > 127) * 255).astype(np.uint8)

    # XOR with each subsequent image
    for i in range(1, len(images)):
        # Convert current image to binary
        current = ((images[i] > 127) * 255).astype(np.uint8)

        # XOR operation
        result = cv2.bitwise_xor(result, current)

        # Save intermediate results if requested
        if save_intermediate and i < len(images) - 1:
            intermediate_path = f'xor_intermediate_{i}.png'
            cv2.imwrite(intermediate_path, result)
            print(f"  Saved intermediate {i}: {intermediate_path}")

            # Try to scan intermediate result
            scan_result = try_scan(result)
            if scan_result:
                print(f"  [+] Intermediate {i} decoded: {scan_result}")

    # Save final result
    output_path = 'xor_result.png'
    cv2.imwrite(output_path, result)
    print(f"\n[+] Final XOR result saved: {output_path}")

    # Try to scan final result
    final_scan = try_scan(result)
    if final_scan:
        print(f"[+] SUCCESS! Decoded: {final_scan}")

        # Check for flag pattern
        flag_patterns = ['flag{', 'FLAG{', 'ctf{', 'CTF{'}
        for pattern in flag_patterns:
            if pattern in final_scan:
                print(f"\n[!!!] FLAG FOUND: {final_scan}")
                break
    else:
        print("[-] Could not decode the XOR result")
        print("    Try:")
        print("    - Inverting the result image")
        print("    - Different image ordering")
        print("    - Manual inspection in an image editor")

    return output_path

def xor_with_operations(image_paths):
    """Try XOR with various preprocessing operations"""
    print("\n[*] Trying XOR with preprocessing variations...")
    print("-" * 50)

    # Load images
    images = []
    for path in image_paths:
        img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            print(f"[!] Failed to load: {path}")
            return None
        images.append(img)

    operations = [
        ('normal', lambda x: x),
        ('inverted', lambda x: cv2.bitwise_not(x)),
        ('threshold_otsu', lambda x: cv2.threshold(x, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]),
        ('threshold_adaptive', lambda x: cv2.adaptiveThreshold(x, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                                              cv2.THRESH_BINARY, 11, 2))
    ]

    for op_name, operation in operations:
        print(f"\n  Trying with {op_name} preprocessing...")

        # Apply operation to all images
        processed = [operation(img.copy()) for img in images]

        # XOR them
        result = processed[0]
        for i in range(1, len(processed)):
            result = cv2.bitwise_xor(result, processed[i])

        # Save and try to scan
        output = f'xor_{op_name}.png'
        cv2.imwrite(output, result)

        scan_result = try_scan(result)
        if scan_result:
            print(f"    [+] SUCCESS with {op_name}! Decoded: {scan_result}")
            return output
        else:
            print(f"    [-] No QR found with {op_name}")

    return None

def analyze_images(image_paths):
    """Analyze images before XOR"""
    print("\n[*] Analyzing input images...")
    print("-" * 50)

    for path in image_paths:
        print(f"\n  {os.path.basename(path)}:")

        try:
            # Load image
            img = cv2.imread(path)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Get statistics
            height, width = gray.shape
            unique_colors = len(np.unique(gray))
            mean_val = np.mean(gray)
            std_val = np.std(gray)

            print(f"    Dimensions: {width}x{height}")
            print(f"    Unique colors: {unique_colors}")
            print(f"    Mean pixel value: {mean_val:.2f}")
            print(f"    Std deviation: {std_val:.2f}")

            # Check if it's already a QR code
            scan_result = try_scan(gray)
            if scan_result:
                print(f"    [!] Already contains QR: {scan_result}")
            else:
                print(f"    [-] No QR code detected")

            # Check if it looks like noise
            if unique_colors > 200 and std_val > 50:
                print(f"    [*] Appears to be noise/random data")
            elif unique_colors <= 2:
                print(f"    [*] Binary image (black and white only)")
            elif unique_colors <= 10:
                print(f"    [*] Limited color palette")

        except Exception as e:
            print(f"    [!] Error analyzing: {e}")

def try_all_combinations(image_paths):
    """Try different combinations of images"""
    print("\n[*] Trying different image combinations...")
    print("-" * 50)

    from itertools import combinations

    # Try pairs
    if len(image_paths) > 2:
        print("\n[*] Trying pairs...")
        for combo in combinations(image_paths, 2):
            print(f"  XORing: {os.path.basename(combo[0])} + {os.path.basename(combo[1])}")

            # Load images
            img1 = cv2.imread(combo[0], cv2.IMREAD_GRAYSCALE)
            img2 = cv2.imread(combo[1], cv2.IMREAD_GRAYSCALE)

            if img1 is None or img2 is None:
                continue

            # Ensure same size
            if img1.shape != img2.shape:
                img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

            # XOR
            result = cv2.bitwise_xor(img1, img2)

            # Try to scan
            scan_result = try_scan(result)
            if scan_result:
                output = f'xor_pair_{os.path.basename(combo[0])[:-4]}_{os.path.basename(combo[1])[:-4]}.png'
                cv2.imwrite(output, result)
                print(f"    [+] SUCCESS! Decoded: {scan_result}")
                print(f"    [+] Saved to: {output}")
                return output

            print(f"    [-] No QR found")

    # Try triples if we have enough images
    if len(image_paths) > 3:
        print("\n[*] Trying triples...")
        for combo in combinations(image_paths, 3):
            names = [os.path.basename(c)[:-4] for c in combo]
            print(f"  XORing: {' + '.join(names)}")

            # Load and XOR
            images = []
            for path in combo:
                img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
                if img is None:
                    break
                images.append(img)

            if len(images) == 3:
                # Resize if needed
                min_h = min(img.shape[0] for img in images)
                min_w = min(img.shape[1] for img in images)
                images = [cv2.resize(img, (min_w, min_h)) for img in images]

                # XOR all three
                result = cv2.bitwise_xor(images[0], images[1])
                result = cv2.bitwise_xor(result, images[2])

                # Try to scan
                scan_result = try_scan(result)
                if scan_result:
                    output = f'xor_triple_{"_".join(names)}.png'
                    cv2.imwrite(output, result)
                    print(f"    [+] SUCCESS! Decoded: {scan_result}")
                    print(f"    [+] Saved to: {output}")
                    return output

                print(f"    [-] No QR found")

    return None

def print_usage():
    """Print usage information"""
    print("\nUsage: python xor_qr.py <image1> <image2> [image3 ...] [options]")
    print("\nOptions:")
    print("  -i, --intermediate   Save intermediate XOR results")
    print("  -a, --analyze       Analyze images before XOR")
    print("  -v, --variations    Try preprocessing variations")
    print("  -c, --combinations  Try different image combinations")
    print("\nExamples:")
    print("  python xor_qr.py noise1.png noise2.png")
    print("  python xor_qr.py qr1.png qr2.png qr3.png --intermediate")
    print("  python xor_qr.py *.png --combinations")
    print("\nNote:")
    print("  XOR operation is performed on binary (black/white) versions")
    print("  of the images. The tool will attempt to decode the result")
    print("  and report if a QR code is found.")

def main():
    """Main function"""
    print_banner()

    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    # Parse arguments
    image_paths = []
    options = []

    for arg in sys.argv[1:]:
        if arg.startswith('-'):
            options.append(arg)
        elif os.path.exists(arg):
            image_paths.append(arg)
        else:
            print(f"[!] Warning: File not found: {arg}")

    if len(image_paths) < 2:
        print("[!] Error: At least 2 images required for XOR")
        sys.exit(1)

    print(f"[*] Found {len(image_paths)} images")

    # Analyze images if requested
    if '-a' in options or '--analyze' in options:
        analyze_images(image_paths)

    # Main XOR operation
    save_intermediate = '-i' in options or '--intermediate' in options
    result = xor_images(image_paths, save_intermediate)

    if result:
        # Try variations if requested
        if '-v' in options or '--variations' in options:
            xor_with_operations(image_paths)

        # Try combinations if requested
        if '-c' in options or '--combinations' in options:
            try_all_combinations(image_paths)

        print("\n[*] XOR operation complete!")
        print(f"[*] Check the output files for results")

        # Try inverting the result
        print("\n[*] Also trying inverted result...")
        result_img = cv2.imread(result, cv2.IMREAD_GRAYSCALE)
        inverted = cv2.bitwise_not(result_img)
        inverted_path = 'xor_result_inverted.png'
        cv2.imwrite(inverted_path, inverted)

        inv_scan = try_scan(inverted)
        if inv_scan:
            print(f"[+] SUCCESS with inverted! Decoded: {inv_scan}")
        else:
            print("[-] No QR in inverted result either")

    else:
        print("\n[!] XOR operation failed")
        print("[*] Check error messages above")

if __name__ == "__main__":
    main()