#!/usr/bin/env python3
"""
GIF/Video Frame Extractor and QR Decoder
Author: QR CTF Toolkit
Version: 1.0

Usage: python frame_extractor.py <gif_or_video_file>

Extracts frames from animated GIFs or videos and decodes QR codes from each frame.
Useful for challenges where data is split across multiple frames.
"""

import sys
import os
from PIL import Image
from pyzbar import pyzbar
import cv2

def extract_gif_frames(gif_path):
    """Extract and decode QR codes from GIF frames"""
    print(f"\n[*] Processing GIF: {gif_path}")
    print("-" * 50)

    flag = ""
    decoded_data = []
    frames_with_qr = 0
    frames_without_qr = 0

    try:
        with Image.open(gif_path) as im:
            total_frames = im.n_frames
            print(f"[*] Total frames: {total_frames}")

            # Create output directory for frames if saving is needed
            output_dir = gif_path.replace('.gif', '_frames')
            save_failed = False

            for i in range(total_frames):
                im.seek(i)

                # Convert to RGB if necessary (some GIFs are in palette mode)
                if im.mode != 'RGB':
                    frame = im.convert('RGB')
                else:
                    frame = im

                # Try to decode QR from frame
                decoded = pyzbar.decode(frame)

                if decoded:
                    frames_with_qr += 1
                    data = decoded[0].data.decode('utf-8', errors='ignore')
                    decoded_data.append((i, data))
                    flag += data

                    print(f"  Frame {i+1:3d}: [+] {data}")
                else:
                    frames_without_qr += 1
                    print(f"  Frame {i+1:3d}: [-] No QR code found")

                    # Save frames without QR for manual inspection
                    if not save_failed and frames_without_qr <= 10:
                        try:
                            if not os.path.exists(output_dir):
                                os.makedirs(output_dir)
                            frame.save(f"{output_dir}/frame_{i:04d}.png")
                        except:
                            save_failed = True

    except Exception as e:
        print(f"[!] Error processing GIF: {e}")
        return None

    print("\n" + "=" * 50)
    print("[*] EXTRACTION SUMMARY")
    print("=" * 50)
    print(f"  Total frames: {total_frames}")
    print(f"  Frames with QR: {frames_with_qr}")
    print(f"  Frames without QR: {frames_without_qr}")

    if flag:
        print(f"\n[+] Concatenated result: {flag}")

        # Check for common flag patterns
        flag_patterns = ['flag{', 'FLAG{', 'ctf{', 'CTF{'}
        for pattern in flag_patterns:
            if pattern in flag:
                print(f"\n[!!!] FLAG FOUND: {flag}")
                break

    if frames_without_qr > 0 and frames_without_qr <= 10:
        print(f"\n[*] Failed frames saved to: {output_dir}/")
        print("    Consider manual inspection of these frames")

    return flag

def extract_video_frames(video_path):
    """Extract and decode QR codes from video frames"""
    print(f"\n[*] Processing video: {video_path}")
    print("-" * 50)

    flag = ""
    decoded_data = []
    frame_count = 0
    frames_with_qr = 0

    try:
        cap = cv2.VideoCapture(video_path)

        if not cap.isOpened():
            print("[!] Error: Could not open video")
            return None

        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        print(f"[*] FPS: {fps}")
        print(f"[*] Total frames: {total_frames}")

        # Process every nth frame based on FPS (to avoid duplicates)
        frame_skip = max(1, int(fps / 2))  # Process 2 frames per second

        while True:
            ret, frame = cap.read()

            if not ret:
                break

            if frame_count % frame_skip == 0:
                # Convert BGR to RGB for pyzbar
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil_image = Image.fromarray(rgb_frame)

                # Try to decode QR
                decoded = pyzbar.decode(pil_image)

                if decoded:
                    frames_with_qr += 1
                    data = decoded[0].data.decode('utf-8', errors='ignore')

                    # Avoid duplicates
                    if not decoded_data or decoded_data[-1][1] != data:
                        decoded_data.append((frame_count, data))
                        flag += data
                        print(f"  Frame {frame_count:5d}: [+] {data}")

            frame_count += 1

        cap.release()

    except Exception as e:
        print(f"[!] Error processing video: {e}")
        return None

    print("\n" + "=" * 50)
    print("[*] VIDEO EXTRACTION SUMMARY")
    print("=" * 50)
    print(f"  Total frames processed: {frame_count}")
    print(f"  Frames with unique QR: {len(decoded_data)}")

    if flag:
        print(f"\n[+] Concatenated result: {flag}")

        # Check for flag patterns
        flag_patterns = ['flag{', 'FLAG{', 'ctf{', 'CTF{'}
        for pattern in flag_patterns:
            if pattern in flag:
                print(f"\n[!!!] FLAG FOUND: {flag}")
                break

    return flag

def extract_all_frames(input_path, output_dir):
    """Extract all frames from GIF/video for manual inspection"""
    print(f"\n[*] Extracting all frames to: {output_dir}")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if input_path.lower().endswith('.gif'):
        # Extract from GIF
        try:
            with Image.open(input_path) as im:
                for i in range(im.n_frames):
                    im.seek(i)
                    frame = im.convert('RGB')
                    output_path = f"{output_dir}/frame_{i:04d}.png"
                    frame.save(output_path)
                    print(f"  Saved frame {i+1}/{im.n_frames}")

            print(f"\n[+] Extracted {im.n_frames} frames")

        except Exception as e:
            print(f"[!] Error: {e}")

    else:
        # Extract from video
        try:
            cap = cv2.VideoCapture(input_path)
            frame_count = 0

            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                output_path = f"{output_dir}/frame_{frame_count:04d}.png"
                cv2.imwrite(output_path, frame)
                frame_count += 1

                if frame_count % 10 == 0:
                    print(f"  Extracted {frame_count} frames...")

            cap.release()
            print(f"\n[+] Extracted {frame_count} frames")

        except Exception as e:
            print(f"[!] Error: {e}")

def analyze_frame_sequence(directory):
    """Analyze a directory of extracted frames"""
    print(f"\n[*] Analyzing frames in: {directory}")
    print("-" * 50)

    import glob

    # Get all image files
    patterns = ['*.png', '*.jpg', '*.jpeg', '*.bmp']
    files = []
    for pattern in patterns:
        files.extend(glob.glob(os.path.join(directory, pattern)))

    files.sort()  # Ensure correct order

    if not files:
        print("[!] No image files found")
        return

    print(f"[*] Found {len(files)} image files")

    flag = ""
    for i, file_path in enumerate(files):
        try:
            img = Image.open(file_path)
            decoded = pyzbar.decode(img)

            if decoded:
                data = decoded[0].data.decode('utf-8', errors='ignore')
                flag += data
                print(f"  {os.path.basename(file_path)}: [+] {data}")
            else:
                print(f"  {os.path.basename(file_path)}: [-] No QR found")

        except Exception as e:
            print(f"  {os.path.basename(file_path)}: [!] Error: {e}")

    if flag:
        print(f"\n[+] Concatenated result: {flag}")

def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════╗
║    Frame Extractor & QR Decoder     ║
║         Animated QR Analysis        ║
╚══════════════════════════════════════╝
    """
    print(banner)

def print_usage():
    """Print usage information"""
    print("Usage: python frame_extractor.py <input_file> [options]")
    print("\nOptions:")
    print("  -e, --extract-all    Extract all frames to directory")
    print("  -d, --directory      Analyze directory of frames")
    print("\nExamples:")
    print("  python frame_extractor.py challenge.gif")
    print("  python frame_extractor.py video.mp4")
    print("  python frame_extractor.py challenge.gif -e")
    print("  python frame_extractor.py -d ./frames/")
    print("\nSupported formats:")
    print("  - GIF animations")
    print("  - Video files (MP4, AVI, MOV, etc.)")
    print("  - Directory of frame images")

def main():
    """Main function"""
    print_banner()

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    # Parse arguments
    extract_all = '-e' in sys.argv or '--extract-all' in sys.argv
    analyze_dir = '-d' in sys.argv or '--directory' in sys.argv

    if analyze_dir:
        # Analyze directory mode
        if len(sys.argv) < 3:
            print("[!] Error: Please specify directory path")
            sys.exit(1)

        directory = sys.argv[2] if sys.argv[1] in ['-d', '--directory'] else sys.argv[1]
        if not os.path.exists(directory):
            print(f"[!] Error: Directory not found: {directory}")
            sys.exit(1)

        analyze_frame_sequence(directory)

    else:
        # File processing mode
        input_file = sys.argv[1]

        if not os.path.exists(input_file):
            print(f"[!] Error: File not found: {input_file}")
            sys.exit(1)

        if extract_all:
            # Extract all frames
            output_dir = input_file.rsplit('.', 1)[0] + '_frames'
            extract_all_frames(input_file, output_dir)

        else:
            # Process and decode frames
            if input_file.lower().endswith('.gif'):
                result = extract_gif_frames(input_file)
            elif input_file.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.webm')):
                result = extract_video_frames(input_file)
            else:
                print("[!] Error: Unsupported file format")
                print("    Supported: GIF, MP4, AVI, MOV, MKV, WEBM")
                sys.exit(1)

            # Save result to file
            if result:
                output_file = input_file.rsplit('.', 1)[0] + '_decoded.txt'
                with open(output_file, 'w') as f:
                    f.write(result)
                print(f"\n[*] Result saved to: {output_file}")

if __name__ == "__main__":
    main()