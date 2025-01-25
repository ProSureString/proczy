# Advanced Proxy Server

## Features

- HTTP/HTTPS Proxying
- WebSocket Support
- Rate Limiting
- IP Blocking
- Advanced Logging
- SSL/TLS Security
- URL Rewriting
- Authentication Hooks

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Modify server settings in the `ProxyServer` class:
- Adjust rate limits
- Configure IP blocking
- Customize logging

## Running the Server

```bash
python main.py
```

Default: 
- Host: 0.0.0.0
- Port: 8080
- Debug: True

## Notes
- Please use in controlled environments(ideally for home or personal use, that's what i created it for.)
- Please create an issue on github for any issue you find!


## Contributing

1. Fork the repository
2. Create feature branches
3. Submit pull requests

## License

Copyright (c) 2025 ProSureString

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.