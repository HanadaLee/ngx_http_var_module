# ngx_http_var_module

## Name

`ngx_http_var_module` is a nginx module that dynamically assigns new variables through predefined functions.

# Table of Content

- [ngx\_http\_var\_module](#ngx_http_var_module)
  - [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
  - [var](#var)
  - [const](#const)
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

**Syntax:** *var $new_variable operator args... \[if\=condition\]*

**Default:** *-*

**Context:** *http, server, location*

Define a variable whose value is the result of function calculation. The variable value cannot be cached and is recalculated each time it is used. If the current level does not define a variable with the same variable name using this instruction, it can be inherited from the previous level.

The following functions are available:
```nginx
# String Operations
var $new_var copy src_str; # Copy the value of a complex variable
var $new_var len src_str; # Length of the string
var $new_var upper src_str; # Convert to uppercase
var $new_var lower src_str; # Convert to lowercase
var $new_var trim src_str; # Trim whitespace or blank characters from both ends
var $new_var ltrim src_str; # Trim whitespace or blank characters from the left
var $new_var rtrim src_str; # Trim whitespace or blank characters from the right
var $new_var reverse src_str; # Reverse the string
var $new_var find src_str sub_str; # Find the starting position of the substring
var $new_var repeat src_str times; # Repeat the string
var $new_var substr src_str start len; # Extract a substring
var $new_var replace src_str src dst; # Replace a keyword

# Regular Expression Operations
var $new_var re_capture src_str capture_regex assign_value; # Regular expression capture
var $new_var re_capture_i src_str capture_regex assign_value; # Regular expression capture (case-insensitive)
var $new_var re_sub src_str capture_regex assign_value; # Regular expression substitution
var $new_var re_sub_i src_str capture_regex assign_value; # Regular expression substitution (case-insensitive)
var $new_var re_gsub src_str capture_regex assign_value; # Regular expression global substitution
var $new_var re_gsub_i src_str capture_regex assign_value; # Regular expression global substitution (case-insensitive)

# Mathematical Calculations
var $new_var abs int; # Absolute value of an integer
var $new_var max int1 int2; # Maximum of two integers
var $new_var min int1 int2; # Minimum of two integers
var $new_var add int1 int2; # Addition of two integers
var $new_var sub int1 int2; # Subtraction of two integers
var $new_var mul int1 int2; # Multiplication of two integers
var $new_var div int1 int2; # Integer division (quotient)
var $new_var mod int1 int2; # Integer division (remainder)
var $new_var round src_num int; # Round to n significant digits
var $new_var floor src_num; # Floor operation, rounds down to the nearest integer
var $new_var ceil src_num; # Ceiling operation, rounds up to the nearest integer
var $new_var rand; # Random large positive integer
var $new_var rand_range start_int end_int; # Random positive integer within a specified range

# Encoding and Decoding Conversions
var $new_var hex_encode src_str; # Convert binary to hexadecimal
var $new_var hex_decode src_str; # Convert hexadecimal to binary
var $new_var dec_to_hex dec; # Decimal to hexadecimal
var $new_var hex_to_dec hex; # Hexadecimal to decimal
var $new_var escape_uri src_str; # Full URI encoding
var $new_var escape_args src_str; # Argument encoding
var $new_var escape_uri_component src_str; # URI component encoding
var $new_var unescape_uri src_str; # URI decoding
var $new_var base64_encode src_str; # Base64 encoding
var $new_var base64url_encode src_str; # Base64 URL encoding
var $new_var base64_decode src_str; # Base64 decoding
var $new_var base64url_decode src_str; # Base64 URL decoding

# Password Hashing
var $new_var crc32_short src_str; # CRC32 encoding
var $new_var crc32_log src_str; # CRC32 encoding
var $new_var md5sum src_str; # MD5 encoding
var $new_var sha1sum src_str; # SHA1 encoding
var $new_var sha256sum src_str; # SHA256 encoding
var $new_var sha384sum src_str; # SHA384 encoding
var $new_var sha512sum src_str; # SHA512 encoding
var $new_var hmac_sha1 src_str secret; # HMAC_SHA1 encryption
var $new_var hmac_sha256 src_str secret; # HMAC_SHA256 encryption

# Time Formatting
var $new_var gmt_time [src_ts] date_format; # Convert timestamp to specified GMT time format (if timestamp is omitted, use current time)
var $new_var gmt_time [src_ts] http_time; # Convert timestamp to HTTP time (if timestamp is omitted, use current time)
var $new_var gmt_time [src_ts] cookie_time; # Convert timestamp to cookie time (if timestamp is omitted, use current time)
var $new_var local_time [src_ts] date_format; # Convert timestamp to specified local time format (if timestamp is omitted, use current time)
var $new_var unixtime; # Return the current timestamp
var $new_var unixtime src_http_time http_time; # Convert HTTP time to timestamp
var $new_var unixtime src_time date_format timezone; # Convert specified date to timestamp (if omitted, returns current timestamp)
```

Variables defined with the var directive can be overwritten by directives such as `set` and `auth_request_set`.

The if parameter enables conditional var. var will not be assign a value if the condition evaluates to “0” or an empty string. And it will continue to look for subsequent definitions of this variable.

```nginx
# When request header A is present, the value of the variable is 'have-header-a'
var $new_var copy have-header-a if=$http_a;

# When request header A is not present but request header B is present, the value of the variable is 'have-header-b'
var $new_var copy have-header-b if=$http_b;

# When both request header A and B are not present, the value of the variable is 'not-have-a-or-b'
var $new_var copy not-have-a-or-b;
add_header Test-Var $new_var;
```

## const

**Syntax:** *const $new_variable operator args... \[if\=condition\]*

**Default:** *-*

**Context:** *http, server, location*

Same as variables defined by the `var` directive, but variables are cacheable, and the value of the variable is only calculated the first time it is used. In addition, the value of the variable cannot be modified.

Do not use both the const and var directives to define variables with the same name.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
