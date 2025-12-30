import sys
import os
import hashlib
import struct

def decode_bps_number(data, offset):
    result = 0
    shift = 1
    while True:
        byte = data[offset]
        offset += 1
        result += (byte & 0x7F) * shift
        if byte & 0x80:
            return result, offset
        shift <<= 7
        result += shift

def apply_bps_patch(source_data, patch_data):
    if patch_data[:4] != b'BPS1':
        raise ValueError("Invalid BPS header.")

    offset = 4
    source_len, offset = decode_bps_number(patch_data, offset)
    target_len, offset = decode_bps_number(patch_data, offset)
    metadata_len, offset = decode_bps_number(patch_data, offset)
    offset += metadata_len

    target_data = bytearray(target_len)
    output_offset = 0
    source_offset = 0
    target_read_offset = 0

    while output_offset < target_len:
        action_code, offset = decode_bps_number(patch_data, offset)
        action = action_code & 3
        length = (action_code >> 2) + 1

        if action == 0:
            target_data[output_offset : output_offset + length] = source_data[output_offset : output_offset + length]
            output_offset += length
        elif action == 1:
            target_data[output_offset : output_offset + length] = patch_data[offset : offset + length]
            output_offset += length
            offset += length
        elif action == 2:
            data, offset = decode_bps_number(patch_data, offset)
            shift = (data >> 1) if not (data & 1) else -(data >> 1)
            source_offset += shift
            target_data[output_offset : output_offset + length] = source_data[source_offset : source_offset + length]
            output_offset += length
            source_offset += length
        elif action == 3:
            data, offset = decode_bps_number(patch_data, offset)
            shift = (data >> 1) if not (data & 1) else -(data >> 1)
            target_read_offset += shift
            for i in range(length):
                target_data[output_offset + i] = target_data[target_read_offset + i]
            output_offset += length
            target_read_offset += length

    return target_data

def normalize_rom(data):
    """Replicates the C++ normalize_data function to ensure we are patching Z64 data."""
    if len(data) < 4:
        return data

    # Read first 4 bytes as Little Endian (Host Order)
    head = struct.unpack('<I', data[:4])[0]
    
    # 0x80371240 in file reads as 0x40123780 on LE Host (Big Endian Z64) -> No Change
    if head == 0x40123780: 
        return data
    
    # 0x37804012 in file reads as 0x12408037 on LE Host (Byte Swapped V64) -> Swap 16
    elif head == 0x12408037: 
        new_data = bytearray(len(data))
        # Swap bytes in pairs (0<->1, 2<->3)
        new_data[0::2] = data[1::2]
        new_data[1::2] = data[0::2]
        return new_data

    # 0x40123780 in file reads as 0x80371240 on LE Host (Little Endian N64) -> Swap 32
    elif head == 0x80371240:
        new_data = bytearray(len(data))
        # Reverse every 4 bytes
        for i in range(0, len(data), 4):
            new_data[i:i+4] = data[i:i+4][::-1]
        return new_data

    return data

def get_mister_diffs(source, target, max_diff=256):
    length = min(len(source), len(target))
    length = (length // 4) * 4 
    
    diffs = []
    
    for i in range(0, length, 4):
        # We use <I (Little Endian) because the MiSTer code casts (uint32_t*)
        # onto the buffer. Since the MiSTer (ARM) is LE, it loads the bytes reversed.
        # We simulate this reversal here so our XOR calculation aligns with theirs.
        s_val = struct.unpack('<I', source[i:i+4])[0]
        t_val = struct.unpack('<I', target[i:i+4])[0]
        
        xor_val = s_val ^ t_val
        
        if xor_val != 0:
            word_idx = i // 4
            # Output word_idx as HEX because the C++ code uses %x to parse it
            diffs.append(f"p{word_idx:x}:{xor_val:08x}")
            
            if len(diffs) > max_diff:
                raise ValueError(f"Too many differences (>{max_diff}). Aborting.")
                
    return diffs

def main():
    if len(sys.argv) < 3:
        print("Usage: patchgen.py <ROM> <BPS/ROM>")
        sys.exit(1)

    path_orig = sys.argv[1]
    path_mod = sys.argv[2]

    with open(path_orig, 'rb') as f:
        source_raw = f.read()

    with open(path_mod, 'rb') as f:
        mod_raw = f.read()

    # 1. Apply BPS if needed
    if mod_raw[:4] == b'BPS1':
        print("Applying BPS patch in memory...")
        target_raw = apply_bps_patch(bytearray(source_raw), bytearray(mod_raw))
    else:
        target_raw = mod_raw

    # 2. Normalize both to Z64 (Big Endian) to match C++ internal memory state
    source_z64 = normalize_rom(source_raw)
    target_z64 = normalize_rom(target_raw)

    # 3. Calculate MD5 of the Z64 formatted source (Code uses normalized buffer for MD5)
    rom_md5 = hashlib.md5(source_z64).hexdigest()

    # 4. Generate Diff
    try:
        diff_list = get_mister_diffs(source_z64, target_z64)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # 5. Output
    if not diff_list:
        print("No differences found.")
    else:
        diff_str = "|".join(diff_list)
        filename = os.path.basename(path_orig)
        print(f"{rom_md5} {diff_str} # {filename}")

if __name__ == "__main__":
    main()