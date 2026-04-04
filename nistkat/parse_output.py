#!/usr/bin/env python3
"""
Parse pk, sk, ct, ss values from test file, compute SHA3-256 hashes,
and generate kat_output_new.inc
"""

import re
import sys
import hashlib

def sha3_256_hash(data_hex):
    """Compute SHA3-256 hash of hex string data"""
    # Convert hex string to bytes
    data_bytes = bytes.fromhex(data_hex)
    
    # Compute SHA3-256 hash
    h = hashlib.sha3_256()
    h.update(data_bytes)
    
    return h.hexdigest()

def parse_test_file(input_file, output_file, max_count=None):
    """Parse test file and extract pk, sk, ct, ss values, compute hashes"""
    
    with open(input_file, 'r') as f:
        content = f.read()
    
    # Split by count to process each test case
    test_cases = re.split(r'count\s*=\s*(\d+)', content)
    
    results = []
    
    # Process pairs (count, data)
    for i in range(1, len(test_cases), 2):
        # Check if we've reached max_count
        if max_count is not None and len(results) >= max_count:
            break
            
        count = test_cases[i]
        data = test_cases[i+1]
        
        # Extract pk, sk, ct, ss (not pk_n, sk_n, ct_n, ss_n)
        # Match everything until end of line
        pk_match = re.search(r'^pk\s*=\s*([0-9a-fA-F]+)', data, re.MULTILINE)
        sk_match = re.search(r'^sk\s*=\s*([0-9a-fA-F]+)', data, re.MULTILINE)
        ct_match = re.search(r'^ct\s*=\s*([0-9a-fA-F]+)', data, re.MULTILINE)
        ss_match = re.search(r'^ss\s*=\s*([0-9a-fA-F]+)', data, re.MULTILINE)
        
        if pk_match and sk_match and ct_match and ss_match:
            pk = pk_match.group(1)
            sk = sk_match.group(1)
            ct = ct_match.group(1)
            ss = ss_match.group(1)
            
            # Compute hashes
            pk_hash = sha3_256_hash(pk)
            sk_hash = sha3_256_hash(sk)
            ct_hash = sha3_256_hash(ct)
            ss_hash = sha3_256_hash(ss)
            
            results.append({
                'count': count,
                'pk_hash': pk_hash,
                'sk_hash': sk_hash,
                'ct_hash': ct_hash,
                'ss_hash': ss_hash
            })
    
    # Write output
    with open(output_file, 'w') as f:
        for result in results:
            f.write(f'"count = {result["count"]}\\n"\n')
            f.write(f'"{result["pk_hash"]}\\n"\n')
            f.write(f'"{result["sk_hash"]}\\n"\n')
            f.write(f'"{result["ct_hash"]}\\n"\n')
            f.write(f'"{result["ss_hash"]}\\n"\n')
    
    print(f"Parsed {len(results)} test cases")
    print(f"Output written to {output_file}")

if __name__ == "__main__":

    input_file = "kat_MLKEM_512.rsp"
    output_file = "kat_512_output_hash.inc"

    max_count = 999

    parse_test_file(input_file, output_file, max_count)


    input_file = "kat_MLKEM_768.rsp"
    output_file = "kat_768_output_hash.inc"

    parse_test_file(input_file, output_file, max_count)

    input_file = "kat_MLKEM_1024.rsp"
    output_file = "kat_1024_output_hash.inc"

    parse_test_file(input_file, output_file, max_count)