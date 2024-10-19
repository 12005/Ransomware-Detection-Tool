import hashlib
import pefile
import re
import math
import requests

# VirusTotal API key (replace with your actual key)
API_KEY = '23f3e5b60239c1afdda7a467a8cc357b4f8112d19408ab7a8823408c6b44ba1b'

def compute_hash(file_path, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def check_file_format(file_path):
    # Check if file is a PE (Portable Executable) format by looking at the first two bytes (DOS header magic)
    with open(file_path, 'rb') as file:
        magic_number = file.read(2)
    return magic_number == b'MZ'

# Function to check hash against VirusTotal database
def check_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        'apikey': API_KEY,
        'resource': file_hash
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response.get('positives', 0) > 0:
            print(f"VirusTotal Detection: {json_response['positives']}/{json_response['total']} engines detected malware.")
            if 'ransomware' in str(json_response).lower():
                return True  # Likely ransomware
        else:
            print("VirusTotal: No malware detected.")
    elif response.status_code == 403:
        print("Error querying VirusTotal: Forbidden (403). Possible reasons: Invalid API key or rate limit exceeded.")
    else:
        print(f"Error querying VirusTotal: {response.status_code}")
    return False

def pe_header_analysis(file_path):
    # Only analyze PE files
    if check_file_format(file_path):
        print("Analyzing PE headers...")
        try:
            pe = pefile.PE(file_path)
            # Perform PE analysis (same as before)
            return []  # Example, replace with actual function results
        except Exception as e:
            print(f"Error inspecting PE headers: {e}")
    else:
        print("File is not a valid PE file. Skipping PE header analysis.")
    return []

def inspect_pe_headers(file_path):
    suspicious_functions = []
    if check_file_format(file_path):  # Only analyze PE files
        try:
            pe = pefile.PE(file_path)
            # Check imported functions for suspicious ones
            suspicious_imports = ["VirtualAlloc", "CreateFileA", "WriteFile", "CryptEncrypt", "CryptDecrypt", "RegCreateKeyA"]
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is not None and imp.name.decode() in suspicious_imports:
                        suspicious_functions.append(imp.name.decode())
        except Exception as e:
            print(f"Error inspecting PE headers: {e}")
    return suspicious_functions

# Module 3: String Extraction
def extract_strings(file_path, min_length=4):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        
        ascii_strings = re.findall(rb'[\x20-\x7E]{%d,}' % min_length, data)
        unicode_strings = re.findall(rb'(?:[\x20-\x7E][\x00]){%d,}' % min_length, data)
        
        all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings] + \
                      [s.decode('utf-16', errors='ignore') for s in unicode_strings]
        
        suspicious_indicators = ["decrypt", "encrypt", "bitcoin", "ransom", "key", "payment"]
        detected_suspicious_strings = [s for s in all_strings if any(indicator in s.lower() for indicator in suspicious_indicators)]
        
        return detected_suspicious_strings
    except Exception as e:
        print(f"Error extracting strings: {e}")
        return []

# Module 4: Entropy Calculation
def calculate_entropy(data):
    if not data:
        return 0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0
    for count in byte_counts:
        if count:
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)

    return entropy

def file_entropy(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        entropy = calculate_entropy(data)
        return entropy
    except Exception as e:
        print(f"Error calculating entropy: {e}")
        return 0
    
# Final ransomware detection script with improved decision-making
def ransomware_static_analysis(file_path):
    print("Starting static analysis...")

    # Variables to store scores for each module
    score = 0
    entropy_threshold = 7.5
    suspicious_threshold = 2  # Total score needed to classify as ransomware

    # Step 1: File Hashing and VirusTotal Check
    print("\n[1] File Hashing and VirusTotal Check")
    hash_value = compute_hash(file_path, 'sha256')
    print(f"SHA-256 Hash: {hash_value}")
    
    # VirusTotal check
    is_ransomware_vt = check_hash_virustotal(hash_value)
    if is_ransomware_vt:
        print("The file is likely ransomware according to VirusTotal.")
        score += 1  # Increase score if VirusTotal flags it

    # Step 2: PE Header Analysis
    print("\n[2] PE Header Analysis")
    suspicious_functions = []  # Initialize to empty list
    if check_file_format(file_path):
        pe_header_analysis(file_path)
        suspicious_functions = inspect_pe_headers(file_path)
        if suspicious_functions:
            print("Suspicious API calls found in imports:")
            for func in suspicious_functions:
                print(f" - {func}")
            score += 1  # Increase score if suspicious API calls are found
        else:
            print("No suspicious API calls detected.")
    else:
        print("PE analysis skipped: File is not a PE.")
    
    # Step 3: String Extraction
    print("\n[3] String Extraction")
    suspicious_strings = extract_strings(file_path)
    if suspicious_strings:
        print("Suspicious strings found:")
        for string in suspicious_strings[:10]:  # Display first 10 strings for brevity
            print(f" - {string}")
        score += 1  # Increase score if suspicious strings are found
    else:
        print("No suspicious strings found.")
    
    # Step 4: Entropy Calculation
    print("\n[4] Entropy Calculation")
    entropy_value = file_entropy(file_path)
    print(f"File entropy: {entropy_value:.4f}")
    
    if entropy_value > entropy_threshold:
        print("High entropy detected (Possible encryption or packing).")
        score += 1  # Increase score if entropy is above the threshold

    # Step 5: Ransomware Likelihood Assessment
    print("\n[5] Ransomware Likelihood Assessment")

    if score >= suspicious_threshold:
        print(f"\nResult: This file is likely ransomware (score: {score}).")
    else:
        print(f"\nResult: This file is not ransomware (score: {score}).")

# Test the full pipeline
file_path = "Submission of project title (Responses).pdf"
ransomware_static_analysis(file_path)

# Test the full pipeline
file_path = "Submission of project title (Responses).pdf"
ransomware_static_analysis(file_path)
