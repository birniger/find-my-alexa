"""Persist pyicloud's session and cookie files in a private S3 bucket."""

from __future__ import annotations

import io
import os
import shutil
import zipfile
from pathlib import Path


SESSION_BUNDLE_NAME = "session-bundle.zip"
MAX_BUNDLE_FILE_SIZE = 5 * 1024 * 1024


class SessionStoreError(RuntimeError):
    """Raised when no usable persisted iCloud session is available."""


def _required_session_files(directory: Path) -> tuple[Path, Path, Path]:
    sessions = sorted(directory.glob("*.session"))
    cookiejars = sorted(directory.glob("*.cookiejar"))
    target = directory / "target.json"
    if len(sessions) != 1 or len(cookiejars) != 1 or not target.is_file():
        raise SessionStoreError("pyicloud did not produce a complete session")
    return sessions[0], cookiejars[0], target


def create_session_bundle(directory: Path) -> io.BytesIO:
    """Build one atomic S3 payload from the session, cookies, and device selection."""
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in _required_session_files(directory):
            archive.write(path, arcname=path.name)
    bundle.seek(0)
    return bundle


def _extract_session_bundle(bundle_path: Path, directory: Path) -> None:
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if (
                len(members) != 3
                or any(Path(name).name != name for name in names)
                or len([name for name in names if name.endswith(".session")]) != 1
                or len([name for name in names if name.endswith(".cookiejar")]) != 1
                or names.count("target.json") != 1
                or any(member.file_size > MAX_BUNDLE_FILE_SIZE for member in members)
            ):
                raise SessionStoreError("The stored session bundle is invalid")

            for member in members:
                destination = directory / member.filename
                destination.write_bytes(archive.read(member))
                destination.chmod(0o600)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise SessionStoreError("The stored session bundle is invalid") from exc

    _required_session_files(directory)


class S3SessionStore:
    def __init__(
        self,
        bucket: str,
        prefix: str = "session/",
        local_directory: Path = Path("/tmp/find-my-alexa-session"),
        client=None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.local_directory = local_directory
        self._client = client
        self._bundle_etag: str | None = None
        self._downloaded_legacy = False

    @property
    def client(self):
        # boto3 is provided by the AWS Lambda runtime.
        if self._client is None:
            import boto3
            from botocore.config import Config

            self._client = boto3.client(
                "s3",
                config=Config(
                    connect_timeout=3,
                    read_timeout=5,
                    retries={"max_attempts": 2, "mode": "standard"},
                ),
            )
        return self._client

    def _resolved_local_directory(self) -> Path:
        directory = self.local_directory.resolve(strict=False)
        temporary_root = Path("/tmp").resolve(strict=False)
        if directory == temporary_root or temporary_root not in directory.parents:
            raise SessionStoreError("Refusing to use an unsafe local session path")
        return directory

    def download(self) -> Path:
        directory = self._resolved_local_directory()

        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)

        paginator = self.client.get_paginator("list_objects_v2")
        direct_objects: dict[str, dict] = {}
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for item in page.get("Contents", []):
                key = item["Key"]
                filename = os.path.basename(key)
                if not filename or filename != key.removeprefix(self.prefix):
                    continue
                direct_objects[filename] = item

        bundle_object = direct_objects.get(SESSION_BUNDLE_NAME)
        if bundle_object:
            etag = bundle_object.get("ETag")
            if not isinstance(etag, str) or not etag:
                raise SessionStoreError("The stored session bundle has no ETag")
            bundle_path = directory / SESSION_BUNDLE_NAME
            self.client.download_file(
                self.bucket,
                bundle_object["Key"],
                str(bundle_path),
            )
            try:
                _extract_session_bundle(bundle_path, directory)
            finally:
                bundle_path.unlink(missing_ok=True)
            self._bundle_etag = etag
            self._downloaded_legacy = False
            return directory

        # Backward-compatible migration path for deployments that predate the
        # atomic bundle. The next successful upload replaces these objects.
        legacy_names = [
            name
            for name in direct_objects
            if name.endswith((".session", ".cookiejar")) or name == "target.json"
        ]
        for name in legacy_names:
            self.client.download_file(
                self.bucket,
                direct_objects[name]["Key"],
                str(directory / name),
            )
        try:
            _required_session_files(directory)
        except SessionStoreError as exc:
            raise SessionStoreError(
                "No complete iCloud session and device selection were found. "
                "Run scripts/authenticate.py."
            ) from exc
        self._bundle_etag = None
        self._downloaded_legacy = True
        return directory

    def upload(self) -> None:
        directory = self._resolved_local_directory()
        files = _required_session_files(directory)
        request = {
            "Body": create_session_bundle(directory).getvalue(),
            "Bucket": self.bucket,
            "Key": f"{self.prefix}{SESSION_BUNDLE_NAME}",
            "ServerSideEncryption": "AES256",
        }
        if self._bundle_etag:
            request["IfMatch"] = self._bundle_etag
        elif self._downloaded_legacy:
            request["IfNoneMatch"] = "*"
        response = self.client.put_object(**request)
        self._bundle_etag = response.get("ETag")

        if not self._downloaded_legacy:
            return

        # Delete legacy top-level objects only during the one-time migration
        # and only after the atomic bundle is durable. Bucket versioning
        # preserves a recoverable noncurrent copy.
        for path in files:
            self.client.delete_object(
                Bucket=self.bucket,
                Key=f"{self.prefix}{path.name}",
            )
        self._downloaded_legacy = False

    def cleanup(self) -> None:
        """Remove downloaded credentials from the Lambda temporary filesystem."""
        shutil.rmtree(self._resolved_local_directory(), ignore_errors=True)
