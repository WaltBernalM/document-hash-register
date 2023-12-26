import re


def valid_hash(s: str, pattern: str) -> bool:
  if not s.startswith('0x'):
    return False
  s_without_prefix = s[2:]
  hex_pattern = re.compile(f'^{pattern}$')  # pattern should be '^[0-9a-fA-F]+$'
  return bool(hex_pattern.match(s_without_prefix)) and len(s_without_prefix) == 64