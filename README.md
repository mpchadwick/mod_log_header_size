# `mod_log_header_size`

An Apache module that provides % directives for logging the size (in bytes) of request and response headers.

## Why?

Intermediaries may impose limits on the amount of bytes that are allowed in the [request](https://maxchadwick.xyz/blog/http-request-header-size-limits) or [response](https://maxchadwick.xyz/blog/http-response-header-size-limits) headers. As a result, it is a good idea to monitor the size amount of bytes being transferred in the request and response headers. This module allows you to log this information, which you later process with an application of your choice.

## Installation

```bash
git clone git@github.com:mpchadwick/mod_log_header_size.git
cd mod_log_header_size
apxs -i -a -c mod_log_header_size.c
```

## Usage

```
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %^IH %^OH" combinedheaderio
CustomLog "/var/log/httpd/access_log" combinedheaderio
```

- `%^IH` - Request header bytes
- `%^OH` - Response header bytes

## Compatibility

Works on both Apache 2.4 and 2.2.

