# httpcat

A simple, HTTP-focused `socat`-like command-line tool.

`httpcat` accepts HTTP requests and passes them to an external command.
The command's standard input receives the request body, and its standard output is returned as the HTTP response.


## Features

- **No dependencies**: Built with only the Go standard library.
- **TLS Support**: Built-in support for HTTPS and client certificate verification.
- **CGI-like Environment**: Passes HTTP request headers and details to the command via CGI 1.1 environment variables.


## Build

```sh
go build .
```


## Usage

```sh
./httpcat listen:<address_spec> exec:"<command_spec>"
```

### Examples

**Basic usage:**
Listen on port 8080 and execute a simple shell script.

```sh
./httpcat listen:8080 exec:"/path/to/script.sh"
```

**With TLS:**
Listen on port 8443 with TLS, and verify client certificate (mTLS).

```sh
./httpcat listen:8443,cert=server.crt,key=server.key,verify,cafile=ca.crt exec:"python3 handle.py"
```


## CGI Environment

Request information is exposed through CGI-compatible environment variables such as:

* `REQUEST_METHOD`
* `REQUEST_URI`
* `QUERY_STRING`
* `CONTENT_TYPE`
* `CONTENT_LENGTH`
* `REMOTE_ADDR`
* `REMOTE_PORT`
* `HTTPS`

HTTP request headers are exported as environment variables using the standard CGI convention.

For example,

```
X-Request-ID: 123
```

becomes

```
HTTP_X_REQUEST_ID=123
```

The request body is provided on standard input.

The executed command should output data to standard output (`stdout`).
If the output begins with an HTTP status line (e.g., `HTTP/1.1 200 OK`) or CGI-like headers followed by a blank line,
`httpcat` will parse them and apply them to the HTTP response.
Otherwise, the entire output is treated as the response body with a `200 OK` status.


## Why?

Tools like `nc` and `socat` are useful for working with raw TCP connections, but sometimes you just want to:

> Receive an HTTP request and pipe it to an arbitrary command.

`httpcat` is a small tool for exactly that use case, without requiring the command itself to implement an HTTP server.


## Design Principles

httpcat is intentionally kept small and self-contained.

* **Standard library only** -- No third-party or external dependencies. It is designed to build with the Go compiler and standard library alone.
* **No routing** -- httpcat does not provide a routing mechanism. Routing can be handled by the command itself.
* **No configuration files** -- httpcat will not introduce configuration files. It should remain quick and easy to run.


## License

0BSD
