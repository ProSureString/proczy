from quart import Quart, render_template, request, Response
import aiohttp

app = Quart(__name__)


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
async def proxy(path):
    # Contstruct the target URL
    target_url = f"{path}"

    # Include