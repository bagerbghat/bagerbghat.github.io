import asyncio
import hashlib
import re
import os
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv
from pydantic import BaseModel
from supabase import create_client, Client

load_dotenv()
supabase: Client = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))


class ScanResult(BaseModel):
    monitor_id: int
    domain: str
    url: str
    status_code: int
    content_hash: str
    has_changed: bool


def clean_html_content(html_content: bytes) -> bytes:
    text = html_content.decode("utf-8", errors="ignore")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    return text.encode("utf-8")


def get_active_monitors():
    """Solo monitores activos, no expirados, ordenados por prioridad."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        resp = (
            supabase.table("monitored_targets")
            .select("*")
            .eq("is_active", True)
            .or_(f"expires_at.is.null,expires_at.gt.{now}")
            .order("priority")
            .execute()
        )
        return resp.data or []
    except Exception as e:
        print(f"[DB Error] No se pudieron cargar monitores: {e}")
        return []


def get_previous_hash(monitor_id: int) -> str | None:
    try:
        resp = (
            supabase.table("price_monitors")
            .select("content_hash")
            .eq("monitor_id", monitor_id)
            .order("checked_at", desc=True)
            .limit(1)
            .execute()
        )
        if resp.data:
            return resp.data[0]["content_hash"]
    except Exception as e:
        print(f"[DB Warning] Historial no disponible para monitor {monitor_id}: {e}")
    return None


def save_to_db(result: ScanResult):
    try:
        supabase.table("price_monitors").insert({
            "monitor_id": result.monitor_id,
            "domain": result.domain,
            "url": result.url,
            "content_hash": result.content_hash,
        }).execute()
    except Exception as e:
        print(f"[DB Error] Fallo al insertar en price_monitors: {e}")


async def check_target(monitor: dict, max_retries: int = 3) -> ScanResult:
    monitor_id = monitor["id"]
    domain = monitor["domain"]
    path = monitor.get("path") or "/"
    vector = monitor.get("vector_name") or "general"
    url = f"https://{domain}{path}"

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
    }

    previous_hash = get_previous_hash(monitor_id)

    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        for attempt in range(max_retries):
            try:
                response = await client.get(url, headers=headers)

                if response.status_code != 200:
                    print(f"[Warning] {url} devolvió HTTP {response.status_code}")
                    return ScanResult(
                        monitor_id=monitor_id, domain=domain, url=url,
                        status_code=response.status_code,
                        content_hash="", has_changed=False,
                    )

                cleaned = clean_html_content(response.content)
                current_hash = hashlib.sha256(cleaned).hexdigest()

                changed = False
                if previous_hash and previous_hash != current_hash:
                    changed = True
                    print(f"[ALERTA] Cambio en {url} (vector: {vector})")
                elif not previous_hash:
                    print(f"[INFO] Línea base creada para {url} (vector: {vector})")
                else:
                    print(f"[INFO] Sin cambios en {url}")

                result = ScanResult(
                    monitor_id=monitor_id, domain=domain, url=str(response.url),
                    status_code=response.status_code,
                    content_hash=current_hash, has_changed=changed,
                )
                save_to_db(result)
                return result

            except (httpx.TimeoutException, httpx.NetworkError) as net_err:
                print(f"[Retry {attempt+1}/{max_retries}] Red en {url}: {net_err}")
                if attempt == max_retries - 1:
                    print(f"[Error Crítico] Sin conexión a {url} tras {max_retries} intentos.")
                    return ScanResult(
                        monitor_id=monitor_id, domain=domain, url=url,
                        status_code=504, content_hash="", has_changed=False,
                    )
                await asyncio.sleep(2 * (attempt + 1))

            except Exception as e:
                print(f"[Error inesperado] {url}: {e}")
                return ScanResult(
                    monitor_id=monitor_id, domain=domain, url=url,
                    status_code=500, content_hash="", has_changed=False,
                )


async def main():
    monitors = get_active_monitors()
    if not monitors:
        print("--- No hay monitores activos. Nada que hacer. ---")
        return

    print(f"--- Iniciando ciclo para {len(monitors)} monitores
