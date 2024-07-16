# H2SinglePacketAttacker

This tool is designed to send HTTP/2 requests in a single packet, which can be useful for testing race conditions attacks. It is based on the work by Amin (https://github.com/nxenon) and his tool [h2spacex](https://github.com/nxenon/h2spacex). This project was created as a practice exercise to better understand the underlying concepts and implementation.

## Features

- Establishes a socket connection, with optional TLS support.
- Sends HTTP/2 connection preface and settings frames.
- Supports GET and POST requests, with customizable headers and data.
- Provides response reading and decompression for gzip, deflate, and Brotli encoded data.
- Includes logging for debugging and error tracking.
- Allows saving the state using pickle files.

## Usage

### Arguments

- `host_name`: The hostname of the server.
- `port_number`: The port number to connect to.
- `--tls_channel`: Enable TLS for the connection.
- `--streams`: Number of streams to use (default: 4).
- `--reading_response_timeout`: Response reading timeout in seconds (default: 4).
- `--scheme`: Specify the URL scheme (http or https).
- `--method`: HTTP method to use (default: GET).
- `--path`: The path to request (default: /).
- `--header`: Add headers to the request. Can be used multiple times.
- `--data`: Data to include in the request body.
- `--get_mode`: Mode for GET requests (0: last byte removal, 1: remove EH flag, 2: use POST with override method header, default: 0).
- `--override_method`: Override method header for GET requests in mode 2.
- `--display_mode`: Mode to display responses (default: 0).
- `--pickle`: Path to a pickle file for saving or loading state (declare path without extension).

### Examples

#### Basic GET Request

```sh
python h2_single_packet_attacker.py example.com 443 --tls_channel --method GET --path /index.html
```

#### POST Request with Data and Headers

```sh
python h2_single_packet_attacker.py example.com 443 --tls_channel --method POST --path /submit --header "Content-Type: application/json" --data '{"key": "value"}'
```

#### Using GET Mode 2 with Method Override

```sh
python h2_single_packet_attacker.py example.com 443 --tls_channel --method GET --path /api --get_mode 2 --override_method x-method-override
```

#### Saving State with Pickle

```sh
python h2_single_packet_attacker.py example.com 443 --tls_channel --method GET --path /index.html --pickle session
```

## Credits

This tool is inspired by the work of Amin (https://github.com/nxenon) and his tool [h2spacex](https://github.com/nxenon/h2spacex). The implementation serves as a learning project to practice the concepts of HTTP/2, network programming and race conditions attacks.
