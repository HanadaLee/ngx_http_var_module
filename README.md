# ngx_http_var_module

## Name

`ngx_http_var_module` is a nginx module that dynamically assigns new variables through predefined functions.

# Table of Content

- [Name](#name)
- [Status](#status)
- [Features](#features)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
  - [var](#var)
- [Author](#author)
- [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
server {
    listen 127.0.0.1:8080;
    server_name localhost;

    location / {
        var $copy_var copy $scheme://$host$request_uri;
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_var_module`.

# Directives

## var

**Syntax:** *var $new_variable operator args...*

**Default:** *-*

**Context:** *http, server, location*

Define a variable whose value is the result of function calculation. The variable value cannot be cached and is recalculated each time it is used. If the current level does not define a variable with the same variable name using this instruction, it can be inherited from the previous level.

The following functions are available:
```nginx
# String Operations
var $new_var copy complex_value; # Copy the value of a complex variable
var $new_var len src_string; # Get length of the string
var $new_var upper src_string; # Convert to uppercase
var $new_var lower src_string; # Convert to lowercase
var $new_var trim src_string; # Remove leading and trailing whitespace
var $new_var ltrim src_string; # Remove leading whitespace
var $new_var rtrim src_string; # Remove trailing whitespace
var $new_var reverse src_string; # Reverse the string
var $new_var position src_string sub_string; # Get the starting position of the substring
var $new_var repeat src_string times; # Repeat the string
var $new_var substr src_string start len; # Extract a substring
var $new_var replace src_string src dst; # Replace a keyword in the string

# Regular Expressions
var $new_var re_capture src_string regex assign_value; # Regex match and capture
var $new_var re_capture_i src_string regex assign_value; # Regex match and capture (case-insensitive)
var $new_var re_sub src_string regex assign_value; # Regex substitution
var $new_var re_sub_i src_string regex assign_value; # Regex substitution (case-insensitive)
var $new_var re_gsub src_string regex assign_value; # Global regex substitution
var $new_var re_gsub_i src_string regex assign_value; # Global regex substitution (case-insensitive)

# Mathematical Calculations
var $new_var abs int; # Absolute value of an integer
var $new_var max int1 int2; # Maximum of two integers
var $new_var min int1 int2; # Minimum of two integers
var $new_var add int1 int2; # Addition of two integers
var $new_var sub int1 int2; # Subtraction of two integers
var $new_var mul int1 int2; # Multiplication of two integers
var $new_var div int1 int2; # Division of two integers (quotient)
var $new_var mod int1 int2; # Division of two integers (remainder)
var $new_var round src_num int; # Round to n significant digits
var $new_var floor src_num; # Round down to the nearest integer
var $new_var ceil src_num; # Round up to the nearest integer
var $new_var rand; # Generate a random positive integer
var $new_var rand_range start_int end_int; # Generate a random positive integer within the specified range

# Encoding and Decoding
var $new_var hex_encode src_string; # Convert binary to hexadecimal
var $new_var hex_decode src_string; # Convert hexadecimal to binary
var $new_var dec_to_hex dec; # Convert decimal to hexadecimal
var $new_var hex_to_dec hex; # Convert hexadecimal to decimal
var $new_var escape_uri src_string; # Encode as complete URI
var $new_var escape_args src_string; # Encode URI parameters
var $new_var escape_uri_component src_string; # Encode URI component
var $new_var unescape_uri src_string; # Decode URI
var $new_var base64_encode src_string; # Base64 encoding
var $new_var base64url_encode src_string; # Base64url encoding
var $new_var base64_decode src_string; # Base64 decoding
var $new_var base64url_decode src_string; # Base64url decoding

# Hashing Calculations
var $new_var crc32_short src_string; # CRC32 encoding, better on relatively short str inputs (i.e., less than 30 ~ 60 bytes)
var $new_var crc32_long src_string; # CRC32 encoding, better on relatively long str inputs (i.e., longer than 30 ~ 60 bytes)
var $new_var md5sum src_string; # MD5 encoding
var $new_var sha1sum src_string; # SHA1 encoding
var $new_var sha256sum src_string; # SHA256 encoding
var $new_var sha384sum src_string; # SHA384 encoding
var $new_var sha512sum src_string; # SHA512 encoding
var $new_var hmac_sha1 src_string secret; # HMAC-SHA1 encryption
var $new_var hmac_sha256 src_string secret; # HMAC-SHA256 encryption

# Time Formatting
var $new_var gmt_time [src_ts] date_format; # Convert timestamp to GMT time in specified format (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] http_time; # Convert timestamp to http time (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] cookie_time; # Convert timestamp to cookie time (current time if timestamp is omitted)
var $new_var local_time [src_ts] date_format; # Convert timestamp to local time in specified format (current time if timestamp is omitted)
var $new_var unixtime; # Return current timestamp
var $new_var unixtime src_http_time http_time; # Convert http time to timestamp
var $new_var unixtime src_time date_format timezone; # Convert specified date to timestamp (current timestamp is returned if all are omitted)
```

Variables defined with the var directive can be overwritten by directives such as `set` and `auth_request_set`.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
