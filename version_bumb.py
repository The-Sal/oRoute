"""Automatically bump the version of oRoute.py and oRoute_daemon.py by 0.1.

Improvements:
- Use stable hashing (SHA-256) instead of Python's built-in hash() which changes every run.
- Ignore the CLIENT_VERSION line when computing file fingerprints so version bumps themselves don't force future bumps.
- Store hashes as a JSON dict {filename: hash} for order independence and robustness.
"""
import os
import json
import hashlib
from typing import Dict, Optional, List

versioned_files: List[str] = [
    'oRoute.py',
    'oRoute_daemon.py'
]

hash_file = 'version_hash.txt'  # kept same name; now stores JSON mapping


def _normalize_content_for_hash(lines: List[str]) -> str:
    """Return content with CLIENT_VERSION line normalized so it doesn't affect the hash."""
    normalized = []
    for line in lines:
        if line.startswith('CLIENT_VERSION = '):
            # Replace the version number with a constant to avoid hash changes due to version bump
            normalized.append('CLIENT_VERSION = 0.0\n')
        else:
            normalized.append(line)
    return ''.join(normalized)


def compute_file_fingerprint(file_path: str) -> Optional[str]:
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r') as f:
        lines = f.readlines()
    content = _normalize_content_for_hash(lines)
    h = hashlib.sha256()
    h.update(content.encode('utf-8'))
    return h.hexdigest()


def load_hashes() -> Optional[Dict[str, str]]:
    """Load stored hashes.

    Supports legacy format (two-line text file) by converting it to a dict in-memory.
    """
    if not os.path.exists(hash_file):
        return None
    try:
        with open(hash_file, 'r') as f:
            data = f.read().strip()
            if not data:
                return None
            # Try JSON first
            try:
                obj = json.loads(data)
                if isinstance(obj, dict):
                    # Ensure all values are strings
                    return {str(k): str(v) for k, v in obj.items()}
            except json.JSONDecodeError:
                pass
            # Fallback: legacy list ordered same as versioned_files
            lines = data.splitlines()
            if len(lines) == len(versioned_files):
                return {versioned_files[i]: lines[i] for i in range(len(versioned_files))}
            # If formats don't match, ignore to avoid accidental bumps
            return None
    except OSError:
        return None


def save_hashes(hashes: Dict[str, str]) -> None:
    try:
        with open(hash_file, 'w') as f:
            json.dump(hashes, f, indent=2, sort_keys=True)
    except OSError as e:
        print(f'Warning: failed to save hashes: {e}')


def bump_version_in_file(file_path: str) -> bool:
    with open(file_path, 'r') as f:
        lines = f.readlines()
    new_lines = []
    version_bumped = False
    new_version = None
    for line in lines:
        if line.startswith('CLIENT_VERSION = '):
            try:
                current_version = float(line.split('=')[1].strip())
            except ValueError:
                # If parsing fails, skip bump for safety
                new_lines.append(line)
                continue
            new_version = round(current_version + 0.1, 1)
            new_lines.append(f'CLIENT_VERSION = {new_version}\n')
            version_bumped = True
        else:
            new_lines.append(line)
    if version_bumped:
        with open(file_path, 'w') as f:
            f.writelines(new_lines)
        print(f'Bumped version in {file_path} to {new_version}')
    else:
        print(f'No version line found in {file_path}')
    return version_bumped


def main():
    previous_hashes = load_hashes()  # dict or None
    current_hashes: Dict[str, str] = {}
    version_bumped_any = False

    for file_path in versioned_files:
        if not os.path.exists(file_path):
            print(f'File {file_path} does not exist.')
            continue

        fingerprint = compute_file_fingerprint(file_path)
        if fingerprint is None:
            print(f'Could not compute fingerprint for {file_path}.')
            continue
        current_hashes[file_path] = fingerprint

        needs_bump = (
            previous_hashes is None or
            previous_hashes.get(file_path) != fingerprint
        )
        if needs_bump:
            if bump_version_in_file(file_path):
                version_bumped_any = True
        else:
            print(f'{file_path} unchanged; no bump needed.')

    if version_bumped_any:
        # Save fingerprints computed with version line normalized; they remain stable after bump
        save_hashes(current_hashes)
    else:
        print('No versions were bumped. All files are up to date.')


if __name__ == '__main__':
    main()