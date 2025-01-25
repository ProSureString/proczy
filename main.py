from quart import Quart, request, Response, render_template
import aiohttp
import logging
from logging.handlers import RotatingFileHandler
import ssl
import asyncio
from typing import Dict, Any
import gzip
import zlib
from bs4 import BeautifulSoup


# Configure logging with rotation
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ProxyServer')
file_handler = RotatingFileHandler('proxy_server.log', maxBytes=5 * 1024 * 1024, backupCount=2)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)


# Rate limiter for client IPs
class RateLimiter:
    def __init__(self, max_requests=200, time_window=60):
        self.request_counts: Dict[str, list[float]] = {}
        self.max_requests = max_requests
        self.time_window = time_window

    async def is_allowed(self, ip: str) -> bool:
        current_time = asyncio.get_event_loop().time()
        if ip not in self.request_counts:
            self.request_counts[ip] = []

        # Remove outdated timestamps
        self.request_counts[ip] = [
            t for t in self.request_counts[ip] if current_time - t <= self.time_window
        ]

        if len(self.request_counts[ip]) >= self.max_requests:
            return False

        # Add current request timestamp
        self.request_counts[ip].append(current_time)
        return True


class ProxyServer:
    def __init__(self):
        self.app = Quart(__name__)
        self.rate_limiter = RateLimiter()
        self.blocked_ips = set()
        self.setup_routes()

    def setup_routes(self):
        """Set up application routes."""
        self.app.add_url_rule('/', defaults={'path': ''}, view_func=self.proxy)
        self.app.add_url_rule('/proxy/<path:path>', view_func=self.proxy)
        self.app.add_url_rule('/ws/<path:path>', view_func=self.websocket_proxy)

    async def proxy(self, path: str):
        """HTTP Proxy route."""
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            return Response("IP Blocked", status=403)

        # Rate limit check
        if not await self.rate_limiter.is_allowed(client_ip):
            return Response("Rate limit exceeded", status=429)

        logger.info(f"Proxy request: {path} from {client_ip}")

        # Handle root path
        if path == "":
            return await render_template('index.html')

        # Rewrite the target URL
        target_url = self.rewrite_url(path)
        request_params = await self.prepare_request_parameters(target_url)

        # Perform proxied request
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(**request_params) as response:
                    return await self.process_response(response)
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return Response(f"Proxy error: {e}", status=500)

    def rewrite_url(self, path: str) -> str:
        """Rewrite and sanitize the target URL."""
        if not path.startswith(('http://', 'https://')):
            path = f"https://{path}"
        return path

    async def prepare_request_parameters(self, target_url: str) -> Dict[str, Any]:
        """Prepare request parameters."""
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in ['host', 'connection']
        }

        # Optional: Rewrite User-Agent
        headers['User-Agent'] = self.rewrite_user_agent(headers.get('User-Agent', ''))

        # Optional: Rewrite X-Frame-Options for display on main page(doesn't work :sob:)
        headers.pop('X-Frame-Options', None)

        return {
            'method': request.method,
            'url': target_url,
            'headers': headers,
            'data': await request.get_data(),
            'cookies': request.cookies,
            'allow_redirects': False,
            'ssl': self.get_ssl_context()
        }

    def rewrite_user_agent(self, original_ua: str) -> str:
        """Rewrite the User-Agent header."""
        return original_ua

    def get_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    async def process_response(self, response):
        """Process and return the proxied response."""
        content = await response.read()
        content = self.decompress_content(content, response.headers.get('Content-Encoding', ''))
        headers = {
            name: value
            for name, value in response.headers.items()
            if name.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        }
        return Response(content, status=response.status, headers=headers)

    def decompress_content(self, content: bytes, encoding: str) -> bytes:
        """Decompress response content."""
        if encoding == 'gzip':
            return gzip.decompress(content)
        elif encoding == 'deflate':
            return zlib.decompress(content)
        return content
    
    def prefix_href_tags(html_content, prefix):
        """Modifies all href attributes in the HTML content by adding the specified prefix."""
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup.find_all("a", href=True):
            original_href = tag["href"]
            # Avoid double-prefixing if the prefix is already present
            if not original_href.startswith(prefix):
                tag["href"] = f"{prefix}{original_href}"
        return str(soup)

    async def websocket_proxy(self, path: str):
        """WebSocket Proxy route."""
        try:
            ws_url = f"wss://{path}"
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url) as remote_ws:
                    local_ws = await request.websocket()
                    async for message in local_ws:
                        await remote_ws.send_str(message)
                        response = await remote_ws.receive()
                        if response.type == aiohttp.WSMsgType.TEXT:
                            await local_ws.send(response.data)
        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")
            return Response(f"WebSocket proxy error: {e}", status=500)

    def run(self, host='0.0.0.0', port=8080, debug=True):
        """Run the proxy server."""
        self.app.run(host=host, port=port, debug=debug)


def main():
    proxy_server = ProxyServer()
    proxy_server.run()


if __name__ == '__main__':
    main()
