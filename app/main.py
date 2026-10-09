from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
from app.routes import files
from app.storage.file_storage import storage_manager

app = FastAPI(
    title="Secure Cloud Storage API - Phase 8",
    description="Phase 8 implementation: Key Revocation & Key Rotation, Fine-Grained Access Control, Dynamic AES-256-GCM Encryption, ECC Key Protection, and Blockchain Management.",
    version="8.0.0"
)


@app.on_event("startup")
def startup_event() -> None:
    """
    Ensure required storage directories are ready when the application starts.
    """
    storage_manager.ensure_upload_dir()


# Register router
app.include_router(files.router)

# Mount static files directory and asset routes
static_dir = Path("static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")
    if (static_dir / "css").exists():
        app.mount("/css", StaticFiles(directory="static/css"), name="css")
    if (static_dir / "js").exists():
        app.mount("/js", StaticFiles(directory="static/js"), name="js")


@app.get("/", tags=["Frontend"])
def serve_root():
    """
    Root endpoint serving the Secure Cloud Storage frontend UI.
    """
    index_path = Path("static/index.html")
    if index_path.exists():
        return FileResponse(index_path)
    return {
        "status": "online",
        "phase": 8,
        "message": "Secure Cloud Storage API (Phase 8 - Key Revocation & Key Rotation) is active.",
        "documentation": "/docs"
    }

