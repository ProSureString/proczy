# Proczy - Open Source Proxy Server

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

(Windows)
1. Clone the repository
2. Navigate to the repository.
    ```bash
    cd proczy
    ```
3. Create a python virtual environment
    ```bash
    python -m venv venv
    ```
4. Activate the virtual environment
    ```bash
    .\venv\Scripts\activate
    ```
5. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Modify settings and constants at the top of the file:
- Adjust rate limits
- Configure IP blocking
- Customize logging
- Set redirect prefix

## Running the Server

```bash
python main.py
```

Default: 
- Host: 0.0.0.0
- Port: 8080
- Debug: True

## Notes
- Please make sure to set config!
- Please use in controlled environments(ideally for home or personal use, that's what i created it for.)
- Please create an issue on github for any issue you find!

## TODOs:

- make it not absolute dogshit
- make it actually fully work
- make it replace all hrefs fully with proxied links
- fix 301's


## Credits
Used the fire effect from [helderman/blend-fire](https://github.com/helderman/blend-fire). (pov: cyteon demand arson)

## Contributing

1. Fork the repository
2. Create feature branches
3. Submit pull requests

## License

Copyright (c) 2025 ProSureString

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.