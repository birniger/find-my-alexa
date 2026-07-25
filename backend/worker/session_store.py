"""Persist pyicloud's session and cookie files in a private S3 bucket."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


class SessionStoreError(RuntimeError):
    """Raised when no usable persisted iCloud session is available."""


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

    @property
    def client(self):
        # boto3 is provided by the AWS Lambda runtime.
        if self._client is None:
            import boto3

            self._client = boto3.client("s3")
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
        found_session = False
        found_cookiejar = False
        found_target = False
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for item in page.get("Contents", []):
                key = item["Key"]
                filename = os.path.basename(key)
                if not filename or filename != key.removeprefix(self.prefix):
                    continue
                if not (
                    filename.endswith((".session", ".cookiejar"))
                    or filename == "target.json"
                ):
                    continue
                self.client.download_file(
                    self.bucket, key, str(directory / filename)
                )
                found_session = found_session or filename.endswith(".session")
                found_cookiejar = found_cookiejar or filename.endswith(".cookiejar")
                found_target = found_target or filename == "target.json"

        if not (found_session and found_cookiejar and found_target):
            raise SessionStoreError(
                "No complete iCloud session and device selection were found. "
                "Run scripts/authenticate.py."
            )
        return directory

    def upload(self) -> None:
        directory = self._resolved_local_directory()
        uploaded = 0
        for path in directory.iterdir():
            if not path.is_file() or not path.name.endswith((".session", ".cookiejar")):
                continue
            self.client.upload_file(
                str(path),
                self.bucket,
                f"{self.prefix}{path.name}",
                ExtraArgs={"ServerSideEncryption": "AES256"},
            )
            uploaded += 1
        if uploaded < 2:
            raise SessionStoreError("pyicloud did not produce a complete session")

    def cleanup(self) -> None:
        """Remove downloaded credentials from the Lambda temporary filesystem."""
        shutil.rmtree(self._resolved_local_directory(), ignore_errors=True)
