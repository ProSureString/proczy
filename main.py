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
import re


# Configure logging with rotation
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ProxyServer')
file_handler = RotatingFileHandler('proxy_server.log', maxBytes=5 * 1024 * 1024, backupCount=2)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)


# Global settings
MAX_REQUESTS = 200
TIME_WINDOW = 60
BLOCKED_IPS = ["0.69.42.0", "10.69.42.0"]
REDIR_PREFIX = "http://127.0.0.1:8080/proxy/"


# Rate limiter for client IPs
class RateLimiter:
    def __init__(self, max_requests=MAX_REQUESTS, time_window=TIME_WINDOW):
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
        #self.blocked_ips = set()
        self.blocked_ips = BLOCKED_IPS
        self.href_prefix = REDIR_PREFIX
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
        headers['User-Agent'] = headers.get('User-Agent', '')

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

        if "text/html" in response.headers.get("Content-Type", ""):
            content = self.replace_srcs(content, response.real_url)
            content = self.replace_hrefs(content, response.real_url)

        return Response(content, status=response.status, headers=headers)

    def decompress_content(self, content: bytes, encoding: str) -> bytes:
        """Decompress response content."""
        if encoding == 'gzip':
            return gzip.decompress(content)
        elif encoding == 'deflate':
            return zlib.decompress(content)
        return content
    
    """

    OLD CODE

    def edit_other_links(self, html_content, current_url=None):
        logger.info(f"Current URL: {current_url}")
        with open("test.txt", "a") as f:
            f.write(f"Current URL: {current_url}\n")

        # Modifies all(only <a> rn lmao) href attributes in the HTML content by adding the specified URL prefix.
        prefix = self.href_prefix
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup.find_all("a", href=True):
            original_href = tag["href"]
            # Avoid double-prefixing if the prefix is already present
            if not original_href.startswith(prefix):
                if original_href.startswith("http"):
                    tag["info"] = f"{prefix}/{original_href}"
                    logger.debug(f"Modified href: {tag['href']}")
                else:
                    tag["href"] = f"{prefix}/{current_url}{original_href}"
                    logger.info(f"Modified href: {tag['href']}")

        return str(soup)
    """
    
    def replace_srcs(self, html_content_b, current_url):

        current_url = str(current_url)

        prefix = self.href_prefix
        html_content = ""

        logger.info(f"Current URL: {current_url}")
        with open("test.txt", "a") as f:
            f.write(f"Current URL: {current_url}\n")
            
        try:
            html_content = html_content_b.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decoding HTML contentsrc: {e}")
            return f"Error decoding HTML contentsrc: {e}"


        def replacement_function(match):
            src = match.group(1)  
            with open("test.txt", "a") as f:
                f.write(f"Current src: {src}\n")
            
            print(src)

            # absolute URLs
            if src.startswith(('http://', 'https://')):
                return f'src="{prefix}{src}"'
            
            # relative URLs
            elif src.startswith('/'):
                # gotta remove potential double slashes don't ask me why
                clean_src = current_url.rstrip('/') + '/' + src.lstrip('/')
                return f'src="{prefix}{clean_src}"'
            
            # relative URLs *without* leading slash
            else:
                clean_src = f"{current_url.rstrip('/')}/{src}"
                return f'src="{prefix}{clean_src}"'
        
        # I *think* pattern should matche src="..." with any content inside the quotes(dpes)
        pattern = r'src="([^"]*)"'

        # replace all matches using the replacement function, pls work(SPOILER, IT WORKS NOW :3)
        return re.sub(pattern, replacement_function, html_content)

    def replace_hrefs(self, html_content, current_url):

        current_url = str(current_url)

        prefix = self.href_prefix

        logger.info(f"Current URL: {current_url}")
        with open("test.txt", "a") as f:
            f.write(f"Current URL: {current_url}\n")

        """
        try:
            html_content = html_content_b.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decoding HTML contenthref: {e}")
            return f"Error decoding HTML contenthref: {e}"
        """

        def replacement_function(match):
            href = match.group(1)  
            with open("test.txt", "a") as f:
                f.write(f"Current href: {href}\n")
            
            print(href)

            # absolute URLs
            if href.startswith(('http://', 'https://')):
                return f'href="{prefix}{href}"'
            
            # relative URLs
            elif href.startswith('/'):
                # gotta remove potential double slashes don't ask me why
                clean_href = current_url.rstrip('/') + '/' + href.lstrip('/')
                return f'href="{prefix}{clean_href}"'
            
            # relative URLs *without* leading slash
            else:
                clean_href = f"{current_url.rstrip('/')}/{href}"
                return f'href="{prefix}{clean_href}"'
        
        # I *think* pattern should matche href="..." with any content inside the quotes(dpes)
        pattern = r'href="([^"]*)"'

        # replace all matches using the replacement function, pls work(SPOILER, IT WORKS NOW :3)
        return re.sub(pattern, replacement_function, html_content)

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
