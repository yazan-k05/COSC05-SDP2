import asyncio
import os
import json
import urllib.error
import urllib.request
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from tiered_xai_ids.shared.config import get_panel_settings
from tiered_xai_ids.shared.logging_config import configure_logging


def create_app() -> FastAPI:
    settings = get_panel_settings()
    attack_client_url = os.getenv("PANEL_ATTACK_CLIENT_URL", "http://attack-client:7000").rstrip("/")
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Tiered IDS Live Panel", version="1.0.0")
    templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates"))
    orchestrator_url = settings.orchestrator_url.rstrip("/")
    global_model_url = settings.global_model_url.rstrip("/")

    def internal_headers() -> dict[str, str]:
        key = settings.internal_api_key.get_secret_value()
        return {"X-Internal-Key": key} if key else {}

    async def proxy_json(
        method: str,
        url: str,
        *,
        payload: dict | list | None = None,
        timeout: float = 8.0,
        include_internal_key: bool = False,
    ) -> JSONResponse:
        headers = {"Content-Type": "application/json"}
        if include_internal_key:
            headers.update(internal_headers())
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                request_kwargs = {"headers": headers}
                if payload is not None:
                    request_kwargs["json"] = payload
                response = await client.request(method, url, **request_kwargs)
        except Exception as exc:
            return JSONResponse(
                status_code=502,
                content={"ok": False, "error": f"panel_proxy_failed: {exc}"},
            )
        try:
            data = response.json() if response.content else {}
        except ValueError:
            data = {"ok": False, "error": "invalid_json_from_upstream", "raw": response.text[:500]}
        return JSONResponse(status_code=response.status_code, content=data)

    async def fetch_live_overview() -> dict:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(f"{orchestrator_url}/api/live/overview")
            response.raise_for_status()
            return response.json()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"service": settings.service_name, "status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="live_panel.html",
            context={
                "request": request,
                "title": "Tiered IDS Live Panel",
                "subtitle": "Dedicated UI app with live WebSocket updates",
                "orchestrator_url": orchestrator_url,
                "global_model_url": global_model_url,
            },
        )

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        return await home(request)

    @app.get("/api/config")
    async def config() -> dict[str, str]:
        return {
            # Browsers should use panel-app as their reachable gateway.  The
            # real service URLs can be WireGuard-only and are used server-side.
            "orchestrator_url": "",
            "global_model_url": "",
            "simulator_url": settings.simulator_url.rstrip("/"),
            "backend_orchestrator_url": orchestrator_url,
            "backend_global_model_url": global_model_url,
        }

    @app.get("/api/live/overview")
    async def live_overview_proxy() -> JSONResponse:
        return await proxy_json("GET", f"{orchestrator_url}/api/live/overview", timeout=10.0)

    @app.websocket("/ws/live")
    async def live_websocket_proxy(websocket: WebSocket) -> None:
        await websocket.accept()
        event_name = "snapshot"
        while True:
            try:
                data = await fetch_live_overview()
                await websocket.send_json({"event": event_name, "data": data})
                event_name = "update"
            except WebSocketDisconnect:
                break
            except Exception as exc:
                try:
                    await websocket.send_json(
                        {
                            "event": "upstream_error",
                            "error": f"orchestrator_unreachable: {exc}",
                        }
                    )
                except Exception:
                    break
            try:
                await asyncio.sleep(2.0)
            except asyncio.CancelledError:
                break

    @app.get("/api/specialist-nodes/state")
    async def specialist_nodes_state_proxy() -> JSONResponse:
        return await proxy_json("GET", f"{orchestrator_url}/api/specialist-nodes/state")

    @app.put("/api/specialist-nodes/toggle")
    async def specialist_nodes_toggle_proxy(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        return await proxy_json("PUT", f"{orchestrator_url}/api/specialist-nodes/toggle", payload=payload)

    @app.post("/api/reset")
    async def reset_proxy() -> JSONResponse:
        return await proxy_json(
            "POST",
            f"{orchestrator_url}/api/reset",
            include_internal_key=True,
        )

    @app.get("/v1/federated/policy")
    async def federated_policy_proxy() -> JSONResponse:
        return await proxy_json("GET", f"{global_model_url}/v1/federated/policy")

    @app.post("/api/master/prompt-master")
    async def prompt_master_proxy(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{attack_client_url}/api/master/prompt-master",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12) as response:
                status_code = response.getcode()
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            raw = exc.read().decode("utf-8") if exc.fp else ""
        except Exception as exc:
            return JSONResponse(
                status_code=502,
                content={"ok": False, "error": f"prompt_master_proxy_failed: {exc}"},
            )
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {"ok": False, "error": "invalid_json_from_attack_client"}
        return JSONResponse(status_code=status_code, content=data)

    @app.post("/api/master/chat")
    async def master_chat_proxy(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{attack_client_url}/api/master/chat",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20) as response:
                status_code = response.getcode()
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            raw = exc.read().decode("utf-8") if exc.fp else ""
        except Exception as exc:
            return JSONResponse(
                status_code=502,
                content={"ok": False, "error": f"master_chat_proxy_failed: {exc}"},
            )
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {"ok": False, "error": "invalid_json_from_attack_client"}
        return JSONResponse(status_code=status_code, content=data)

    return app


app = create_app()
