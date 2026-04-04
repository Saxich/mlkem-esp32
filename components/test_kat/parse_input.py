#!/usr/bin/env python3
"""
Parse z, d, and msg values from test file and generate kat_input_new.inc
"""

import re
import sys

def parse_test_file(input_file, output_file, max_count=None):
    """Parse test file and extract z, d, msg values"""
    
    with open(input_file, 'r') as f:
        content = f.read()
    
    # Find all test cases
    pattern = r'count\s*=\s*(\d+)\s+z\s*=\s*([0-9a-fA-F]+)\s+d\s*=\s*([0-9a-fA-F]+)\s+msg\s*=\s*([0-9a-fA-F]+)'
    
    matches = re.findall(pattern, content, re.MULTILINE)
    
    # Limit to first max_count if specified
    if max_count is not None:
        matches = matches[:max_count]
    
    with open(output_file, 'w') as f:
        for count, z, d, msg in matches:
            f.write(f'"count = {count}\\n"\n')
            f.write(f'"{z}\\n"\n')
            f.write(f'"{d}\\n"\n')
            f.write(f'"{msg}\\n"\n')
    
    print(f"Parsed {len(matches)} test cases")
    print(f"Output written to {output_file}")

if __name__ == "__main__":

    
    input_file = "kat_MLKEM_512.rsp"
    output_file = "kat_input_vectors.inc"

    max_count = 999
    
    parse_test_file(input_file, output_file, max_count)