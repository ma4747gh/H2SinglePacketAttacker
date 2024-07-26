# H2SinglePacketAttacker

## Description

This tool is designed to send HTTP/2 requests in a single packet, which is useful for testing race condition attacks. It is developed to assist in scenarios where you need to perform race condition attacks by leveraging the HTTP/2 protocol. The tool is based on the work by Amin (https://github.com/nxenon) and his tool [h2spacex](https://github.com/nxenon/h2spacex), but it adds more flexibility. It supports sending multiple requests to a single endpoint using a wordlist, sending multiple requests to multiple endpoints, utilizing both GET and POST methods, and sending empty POST requests.

## Features

- CLI-based
- Send HTTP/2 requests in a single packet.
- Includes support for adding custom headers and data.
- Includes different modes for handling GET requests.
- Send multiple requests to a single endpoint using a wordlist.
- Send multiple requests to multiple endpoints.
- Support for both GET and POST methods.
- Ability to send empty POST requests.
- Pickle functionality for saving or loading tool state.

## Usage

```
usage: tool.py [-h] [--tls_channel] [--streams STREAMS] [--reading_response_timeout READING_RESPONSE_TIMEOUT]
               [--scheme {http,https}] [--method {GET,POST}] [--path PATH] [--header HEADER]
               [--data DATA] [--variable_data_key VARIABLE_DATA_KEY] [--word_list WORD_LIST]
               [--multiple_endpoint_mode] [--get_mode {0,1,2}] [--override_method {x-method-override,x-http-method-override}]
               [--display_mode {0,1}] [--pickle PICKLE]
               host_name port_number

Tool to send HTTP/2 requests in a single packet, useful for testing race condition attacks.

positional arguments:
  host_name             The hostname of the server.
  port_number           The port number to connect to.

optional arguments:
  -h, --help            show this help message and exit
  --tls_channel         Enable TLS for the connection.
  --streams STREAMS     Number of streams to use (default: 4).
  --reading_response_timeout READING_RESPONSE_TIMEOUT
                        Response reading timeout in seconds (default: 4).
  --scheme {http,https} Specify the URL scheme (http or https).
  --method {GET,POST}   HTTP method to use (default: GET).
  --path PATH           The path to request (default: /).
  --header HEADER       Add headers to the request. Can be used multiple times.
  --data DATA           Data to include in the request body.
  --variable_data_key VARIABLE_DATA_KEY
                        Key in the request data to be replaced with items from the word list.
  --word_list WORD_LIST Path to a file containing words to be used in place of the variable data key.
  --multiple_endpoint_mode
                        Enable mode to send requests to multiple endpoints.
  --get_mode {0,1,2}    Mode for GET requests (0: last byte removal, 1: remove EH flag, 2: use POST with override method header, default: 0).
  --override_method {x-method-override,x-http-method-override}
                        Override method header for GET requests in mode 2.
  --display_mode {0,1}  Mode to display responses (0: normal, 1: detailed).
  --pickle PICKLE       Path to a pickle file for saving or loading state (declare path without extension).

## Repository Link

For Python scripts to solve race condition vulnerabilities on PortSwigger utilizing this tool, please visit the following repository:

[PortSwigger Race Conditions Lab Scripts](https://github.com/your-username/portswigger-race-conditions)

## Author

Coded by Mohamed Ahmed (ma4747gh).

```

## Repository Link

For Python scripts to solve race condition vulnerabilities on PortSwigger utilizing this tool, please visit the following repository:

[PortSwigger 'Race conditions' Labs Scripts](https://github.com/ma4747gh/PenetrationTestingScripts/tree/main/PortSwigger/Server-side%20topics/Race%20conditions)

## Credits

This tool is inspired by the work of Amin (https://github.com/nxenon) and his tool [h2spacex](https://github.com/nxenon/h2spacex).

## Author

Coded by Mohamed Ahmed (ma4747gh).
