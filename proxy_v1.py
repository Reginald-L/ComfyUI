import argparse
import asyncio
import contextlib
import os
import shlex
import signal
import sys
from urllib.parse import urlsplit

from aiohttp import web, ClientSession, WSMsgType


HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def strip_prefix(path: str, prefix: str) -> str | None:
    """
    Strip a leading prefix if present. If the platform injects extra path
    segments (e.g. /.../8188/v1/...), also strip the last segment equal to
    prefix. Returns the remaining path starting with '/'.
    """
    if path.startswith(prefix):
        rest = path[len(prefix) :]
        return rest if rest else "/"

    seg = prefix.strip("/")
    parts = path.split("/")
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] == seg:
            rest_parts = parts[i + 1 :]
            return "/" + "/".join(rest_parts) if rest_parts else "/"
    return None


async def on_startup(app: web.Application):
    app["session"] = ClientSession()


async def on_cleanup(app: web.Application):
    await app["session"].close()


async def proxy_http(request: web.Request) -> web.StreamResponse:
    prefix = request.app["prefix"]
    target = request.app["target"]
    raw_path = request.rel_url.raw_path
    rest = strip_prefix(raw_path, prefix)
    if rest is None:
        if request.rel_url.path in ("/", ""):
            raise web.HTTPFound(prefix + "/")
        raise web.HTTPNotFound()

    url = target + rest
    if request.rel_url.query_string:
        url += "?" + request.rel_url.query_string

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in HOP_HEADERS
    }
    # If the incoming Host is loopback but Origin is external, rewrite Host to
    # match Origin to avoid ComfyUI's loopback CSRF guard.
    host_val = headers.get("Host", "")
    origin_val = headers.get("Origin", "")
    if host_val and origin_val:
        host_name = host_val.split(":", 1)[0].strip("[]").lower()
        if host_name in ("localhost", "127.0.0.1", "::1") or host_name.startswith("127."):
            try:
                o = urlsplit(origin_val)
                if o.hostname:
                    new_host = o.hostname
                    if o.port:
                        new_host += f":{o.port}"
                    headers["Host"] = new_host
            except Exception:
                pass
    # Standard reverse-proxy headers (don't overwrite if already present).
    remote = request.remote or ""
    if remote:
        xfwd_for = headers.get("X-Forwarded-For")
        headers["X-Forwarded-For"] = f"{xfwd_for}, {remote}" if xfwd_for else remote
    if "X-Forwarded-Host" not in headers and "Host" in request.headers:
        headers["X-Forwarded-Host"] = request.headers["Host"]
    if "X-Forwarded-Proto" not in headers:
        headers["X-Forwarded-Proto"] = request.scheme

    async with request.app["session"].request(
        request.method,
        url,
        headers=headers,
        data=request.content.iter_any(),
        allow_redirects=False,
    ) as resp:
        resp_headers = {
            k: v for k, v in resp.headers.items() if k.lower() not in HOP_HEADERS
        }
        out = web.StreamResponse(
            status=resp.status, reason=resp.reason, headers=resp_headers
        )
        await out.prepare(request)
        async for chunk in resp.content.iter_chunked(8192):
            await out.write(chunk)
        await out.write_eof()
        return out


async def proxy_ws(request: web.Request) -> web.WebSocketResponse:
    prefix = request.app["prefix"]
    target_ws = request.app["target_ws"]
    raw_path = request.rel_url.raw_path
    rest = strip_prefix(raw_path, prefix)
    if rest is None:
        raise web.HTTPNotFound()

    backend_url = target_ws + rest
    if request.rel_url.query_string:
        backend_url += "?" + request.rel_url.query_string

    ws_server = web.WebSocketResponse(autoping=False, max_msg_size=0)
    await ws_server.prepare(request)

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in HOP_HEADERS
    }
    host_val = headers.get("Host", "")
    origin_val = headers.get("Origin", "")
    if host_val and origin_val:
        host_name = host_val.split(":", 1)[0].strip("[]").lower()
        if host_name in ("localhost", "127.0.0.1", "::1") or host_name.startswith("127."):
            try:
                o = urlsplit(origin_val)
                if o.hostname:
                    new_host = o.hostname
                    if o.port:
                        new_host += f":{o.port}"
                    headers["Host"] = new_host
            except Exception:
                pass
    remote = request.remote or ""
    if remote:
        xfwd_for = headers.get("X-Forwarded-For")
        headers["X-Forwarded-For"] = f"{xfwd_for}, {remote}" if xfwd_for else remote
    if "X-Forwarded-Host" not in headers and "Host" in request.headers:
        headers["X-Forwarded-Host"] = request.headers["Host"]
    if "X-Forwarded-Proto" not in headers:
        headers["X-Forwarded-Proto"] = request.scheme

    async with request.app["session"].ws_connect(
        backend_url, headers=headers, autoping=False, max_msg_size=0
    ) as ws_client:

        async def c2b():
            async for msg in ws_server:
                if msg.type == WSMsgType.TEXT:
                    await ws_client.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await ws_client.send_bytes(msg.data)
                elif msg.type == WSMsgType.CLOSE:
                    await ws_client.close()

        async def b2c():
            async for msg in ws_client:
                if msg.type == WSMsgType.TEXT:
                    await ws_server.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await ws_server.send_bytes(msg.data)
                elif msg.type == WSMsgType.CLOSE:
                    await ws_server.close()

        await asyncio.gather(c2b(), b2c())

    return ws_server


@web.middleware
async def dispatch(request: web.Request, handler):
    ws_probe = web.WebSocketResponse()
    if ws_probe.can_prepare(request).ok:
        return await proxy_ws(request)
    return await proxy_http(request)


def build_proxy_app(prefix: str, target: str) -> web.Application:
    target_ws = target.replace("http://", "ws://").replace("https://", "wss://")
    app = web.Application(middlewares=[dispatch])
    app["prefix"] = prefix
    app["target"] = target
    app["target_ws"] = target_ws
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


async def stream_process_output(proc: asyncio.subprocess.Process, name: str):
    if proc.stdout is None:
        return
    async for raw in proc.stdout:
        try:
            line = raw.decode(errors="ignore").rstrip()
        except Exception:
            line = str(raw)
        if line:
            print(f"[{name}] {line}", flush=True)


async def wait_for_ready(
    url: str,
    timeout: float,
    stop_event: asyncio.Event | None = None,
    proc: asyncio.subprocess.Process | None = None,
):
    start = asyncio.get_event_loop().time()
    delay = 1.0
    async with ClientSession() as session:
        while True:
            if stop_event is not None and stop_event.is_set():
                raise asyncio.CancelledError()
            if proc is not None and proc.returncode is not None:
                raise RuntimeError(f"ComfyUI exited before ready (code {proc.returncode})")
            try:
                async with session.get(url, timeout=5) as resp:
                    if resp.status < 500:
                        print(f"[launcher] ComfyUI ready: {url} ({resp.status})", flush=True)
                        return
            except Exception:
                pass

            if asyncio.get_event_loop().time() - start > timeout:
                raise TimeoutError(f"ComfyUI not ready after {timeout}s: {url}")
            await asyncio.sleep(delay)
            delay = min(delay * 1.2, 5.0)


async def start_comfyui_subprocess(listen: str, port: int, extra_args: str):
    # Recommended defaults for H100-class GPUs (can be overridden by --comfy-extra-args).
    default_args = [
        "--disable-metadata",
        "--gpu-only",
        "--disable-async-offload",
        "--fast",
    ]
    cmd = [
        "/root/.local/bin/uv",
        "run",
        "main.py",
        "--listen",
        listen,
        "--port",
        str(port),
        "--disable-auto-launch",
        *default_args,
    ]
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    print(f"[launcher] Starting ComfyUI: {' '.join(cmd)}", flush=True)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
    )
    log_task = asyncio.create_task(stream_process_output(proc, "comfyui"))
    return proc, log_task


async def serve_proxy(host: str, port: int, prefix: str, target: str, shutdown_timeout: float = 3.0):
    app = build_proxy_app(prefix, target)
    # Reduce default aiohttp shutdown timeout (60s) so Ctrl+C exits promptly even with open WS.
    runner = web.AppRunner(app, shutdown_timeout=shutdown_timeout)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()
    print(f"[launcher] Proxy listening on http://{host}:{port}{prefix}/ -> {target}/", flush=True)
    return runner


async def async_main():
    parser = argparse.ArgumentParser(description="Reverse proxy /v1 -> local ComfyUI (optional auto-launch)")
    parser.add_argument("--listen", default="0.0.0.0:8188", help="Proxy listen host:port")
    parser.add_argument("--prefix", default="v1", help="External prefix path, e.g. v1")
    parser.add_argument("--target", default="http://127.0.0.1:8189", help="Internal ComfyUI base URL")
    parser.add_argument(
        "--start-comfy",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto-start ComfyUI if not already running (use --no-start-comfy to disable)",
    )
    parser.add_argument("--comfy-listen", default=None, help="ComfyUI listen IP (default from --target)")
    parser.add_argument("--comfy-port", type=int, default=None, help="ComfyUI listen port (default from --target)")
    parser.add_argument("--comfy-extra-args", default="", help="Extra args passed to main.py")
    parser.add_argument("--ready-timeout", type=float, default=300.0, help="Seconds to wait for ComfyUI ready")
    parser.add_argument("--ready-path", default="/", help="Path to probe for readiness")
    parser.add_argument("--proxy-shutdown-timeout", type=float, default=3.0, help="Seconds to wait for proxy shutdown on Ctrl+C")
    args = parser.parse_args()

    # Process handles (initialized early so signal handler can see them).
    comfy_proc: asyncio.subprocess.Process | None = None
    comfy_log_task: asyncio.Task | None = None
    proxy_runner: web.AppRunner | None = None
    monitor_task: asyncio.Task | None = None

    stop_event = asyncio.Event()
    signal_count = 0
    force_task: asyncio.Task | None = None

    def force_kill_now():
        """Hard kill ComfyUI + exit proxy immediately."""
        nonlocal comfy_proc
        if comfy_proc and comfy_proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(comfy_proc.pid, signal.SIGKILL)
        os._exit(0)

    async def force_kill_after(delay: float):
        await asyncio.sleep(delay)
        print("[launcher] Force killing after timeout...", flush=True)
        force_kill_now()

    def _stop(*_):
        nonlocal signal_count, force_task
        signal_count += 1
        stop_event.set()
        if signal_count >= 2:
            print("[launcher] Second Ctrl+C -> force exit.", flush=True)
            force_kill_now()
        if force_task is None:
            # If graceful shutdown hangs (open WS/long requests), force kill soon.
            force_task = asyncio.create_task(
                force_kill_after(args.proxy_shutdown_timeout + 5.0)
            )

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _stop)

    proxy_host, proxy_port_str = args.listen.split(":")
    proxy_port = int(proxy_port_str)
    prefix = "/" + args.prefix.strip("/")
    target = args.target.rstrip("/")

    target_parts = urlsplit(target)
    comfy_host = args.comfy_listen or (target_parts.hostname or "127.0.0.1")
    comfy_port = args.comfy_port or (target_parts.port or 8189)

    ready_url = f"{target}{args.ready_path}"

    try:
        if args.start_comfy and not stop_event.is_set():
            # If ComfyUI is already reachable, don't start another.
            try:
                await wait_for_ready(ready_url, timeout=5.0, stop_event=stop_event)
                print("[launcher] ComfyUI already running; skip auto-start.", flush=True)
            except Exception:
                comfy_proc, comfy_log_task = await start_comfyui_subprocess(
                    comfy_host, comfy_port, args.comfy_extra_args
                )

        if stop_event.is_set():
            return

        # Wait until ComfyUI port is ready before starting proxy.
        await wait_for_ready(
            ready_url,
            timeout=args.ready_timeout,
            stop_event=stop_event,
            proc=comfy_proc,
        )

        if stop_event.is_set():
            return

        proxy_runner = await serve_proxy(
            proxy_host,
            proxy_port,
            prefix,
            target,
            shutdown_timeout=args.proxy_shutdown_timeout,
        )

        if comfy_proc:
            async def monitor_comfy():
                code = await comfy_proc.wait()
                print(f"[launcher] ComfyUI exited with code {code}", flush=True)
                stop_event.set()
            monitor_task = asyncio.create_task(monitor_comfy())

        await stop_event.wait()
    finally:
        print("[launcher] Shutting down...", flush=True)
        if proxy_runner is not None:
            await proxy_runner.cleanup()
        if monitor_task is not None:
            monitor_task.cancel()
        if comfy_log_task is not None:
            comfy_log_task.cancel()
        if comfy_proc and comfy_proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                comfy_proc.terminate()
            try:
                await asyncio.wait_for(comfy_proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(comfy_proc.pid, signal.SIGKILL)
        if force_task is not None:
            force_task.cancel()


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
