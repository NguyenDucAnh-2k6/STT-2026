"""Version the complete ES-module graph so browsers cannot mix old components."""
import asyncio
import hashlib
import re
from pathlib import Path

from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

IMPORT = re.compile(r"((?:from\s*|import\s*\(\s*|import\s*)[\"'])(\.[^\"'?]+\.js)([\"'])")


class DashboardAssets(StaticFiles):
    def __init__(self, directory: str) -> None:
        super().__init__(directory=directory)
        digest = hashlib.sha256()
        for path in sorted(Path(directory).rglob("*.js")):
            digest.update(path.relative_to(directory).as_posix().encode())
            digest.update(path.read_bytes())
        self.revision = digest.hexdigest()[:16]

    async def get_response(self, path: str, scope: dict) -> Response:
        # A response transformed below must not use the source file's old ETag.
        request_scope = dict(scope)
        request_scope["headers"] = [(key, value) for key, value in scope.get("headers", [])
            if key.lower() not in (b"if-none-match", b"if-modified-since")]
        response = await super().get_response(path, request_scope)
        if path.endswith(".js") and isinstance(response, FileResponse):
            source = await asyncio.to_thread(Path(response.path).read_text, encoding="utf-8")
            source = IMPORT.sub(lambda match: f"{match[1]}{match[2]}?v={self.revision}{match[3]}", source)
            return Response(source, media_type="text/javascript", headers={"Cache-Control": "no-store"})
        return response
