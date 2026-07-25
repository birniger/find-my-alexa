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
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.local_directory = local_directory

    @property
    def client(self):
        # boto3 is provided by the AWS Lambda runtime.
        import boto3

        return boto3.client("s3")

    def download(self) -> Path:
        if self.local_directory == Path("/") or not str(self.local_directory).startswith(
            "/tmp/"
        ):
            raise SessionStoreError("Refusing to use an unsafe local session path")

        shutil.rmtree(self.local_directory, ignore_errors=True)
        self.local_directory.mkdir(mode=0o700, parents=True, exist_ok=True)

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
                    self.bucket, key, str(self.local_directory / filename)
                )
                found_session = found_session or filename.endswith(".session")
                found_cookiejar = found_cookiejar or filename.endswith(".cookiejar")
                found_target = found_target or filename == "target.json"

        if not (found_session and found_cookiejar and found_target):
            raise SessionStoreError(
                "No complete iCloud session and device selection were found. "
                "Run scripts/authenticate.py."
            )
        return self.local_directory

    def upload(self) -> None:
        uploaded = 0
        for path in self.local_directory.iterdir():
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
