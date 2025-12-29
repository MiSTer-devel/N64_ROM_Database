import sys
import os
import hashlib
import struct

def decode_bps_number(data, offset):
	"""Decodes a variable-length integer from BPS data."""
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
	"""Applies a BPS patch to source_data and returns the target bytearray."""
	if patch_data[:4] != b'BPS1':
		raise ValueError("Invalid BPS header.")

	offset = 4
	source_len, offset = decode_bps_number(patch_data, offset)
	target_len, offset = decode_bps_number(patch_data, offset)
	metadata_len, offset = decode_bps_number(patch_data, offset)
	offset += metadata_len # Skip metadata

	target_data = bytearray(target_len)
	
	output_offset = 0
	source_offset = 0
	target_read_offset = 0

	while output_offset < target_len:
		action_code, offset = decode_bps_number(patch_data, offset)
		action = action_code & 3
		length = (action_code >> 2) + 1

		if action == 0: # SourceRead
			# Copy bytes from source ROM to target ROM
			chunk = source_data[output_offset : output_offset + length]
			target_data[output_offset : output_offset + length] = chunk
			output_offset += length

		elif action == 1: # TargetRead
			# Read bytes directly from the patch file
			chunk = patch_data[offset : offset + length]
			target_data[output_offset : output_offset + length] = chunk
			output_offset += length
			offset += length

		elif action == 2: # SourceCopy
			# Copy data from anywhere in source
			data, offset = decode_bps_number(patch_data, offset)
			# Map encoded int to positive/negative shift
			shift = (data >> 1)
			if data & 1:
				shift = -shift
			source_offset += shift
			
			chunk = source_data[source_offset : source_offset + length]
			target_data[output_offset : output_offset + length] = chunk
			
			output_offset += length
			source_offset += length

		elif action == 3: # TargetCopy
			# Copy data from already written parts of target
			data, offset = decode_bps_number(patch_data, offset)
			shift = (data >> 1)
			if data & 1:
				shift = -shift
			target_read_offset += shift
			
			# Since we might copy from overlapping regions, we do it byte by byte
			# or careful slicing. Python slices create copies, so safe for simple overlaps.
			# But specific run-length patterns might require loops.
			for i in range(length):
				target_data[output_offset + i] = target_data[target_read_offset + i]
			
			output_offset += length
			target_read_offset += length

	return target_data

def get_xor_diff(source, target, max_diff=256):
	"""Compares two bytearrays and returns XOR deltas."""
	
	# Handle size mismatches by padding the shorter one with nulls for comparison
	max_len = max(len(source), len(target))
	diffs = []
	
	diff_count = 0
	
	i = 0
	while i < max_len:
		b_src = source[i] if i < len(source) else 0
		b_tgt = target[i] if i < len(target) else 0
		
		if b_src != b_tgt:
			xor_val = b_src ^ b_tgt
			
			# Start a contiguous block
			block_start = i
			block_vals = [xor_val]
			diff_count += 1
			
			# Look ahead for contiguous differences
			j = i + 1
			while j < max_len:
				b_src_next = source[j] if j < len(source) else 0
				b_tgt_next = target[j] if j < len(target) else 0
				
				if b_src_next != b_tgt_next:
					block_vals.append(b_src_next ^ b_tgt_next)
					diff_count += 1
					if diff_count > max_diff:
						raise ValueError(f"Too many differences (>{max_diff}). Aborting.")
					j += 1
				else:
					break
			
			# Store the block
			diffs.append((block_start, block_vals))
			i = j
		else:
			i += 1
			
	return diffs

def main():
	if len(sys.argv) < 3:
		print("Usage: python xordiff.py <ROM.z64> <PATCH.bps or MOD.z64>")
		sys.exit(1)

	rom_path = sys.argv[1]
	file2_path = sys.argv[2]

	if not os.path.exists(rom_path) or not os.path.exists(file2_path):
		print("Error: Input files not found.")
		sys.exit(1)

	# 1. Load Original ROM
	with open(rom_path, 'rb') as f:
		source_bytes = bytearray(f.read())

	# 2. Calculate MD5 of Original ROM
	rom_md5 = hashlib.md5(source_bytes).hexdigest()

	# 3. Load File 2 (Check if BPS or ROM)
	with open(file2_path, 'rb') as f:
		file2_bytes = bytearray(f.read())

	target_bytes = None

	# Check for BPS Header "BPS1"
	if file2_bytes[:4] == b'BPS1':
		try:
			target_bytes = apply_bps_patch(source_bytes, file2_bytes)
		except Exception as e:
			print(f"Error applying BPS patch: {e}")
			sys.exit(1)
	else:
		# Assume it's a pre-patched ROM
		target_bytes = file2_bytes

	# 4. Calculate Differences
	try:
		diffs = get_xor_diff(source_bytes, target_bytes, max_diff=1024)
	except ValueError as e:
		print(f"Error: {e}")
		sys.exit(1)

	# 5. Format Output
	# Format: pOFFSET:HEXVAL
	output_parts = []
	
	for offset, vals in diffs:
		hex_str = "".join(f"{b:02x}" for b in vals)
		output_parts.append(f"p{offset}:{hex_str}")

	diff_str = "|".join(output_parts)
	filename = os.path.basename(rom_path)
	
	print(f"{rom_md5} {diff_str} # {filename}")

if __name__ == "__main__":
	main()