# Name

`ngx_http_var_module` is a nginx module that dynamically assigns new variables through predefined functions.

# Table of Content

- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
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

**Syntax:** *var $new_variable operator \[-i\] args... \[if\=condition\]*

**Default:** *-*

**Context:** *http, server, location*

Define a variable whose value is the result of function calculation. The variable value cannot be cached and is recalculated each time it is used. If the current level does not define a variable with the same variable name using this instruction, it can be inherited from the previous level. The -i parameter is used to ignore case.

The following functions are available:
```nginx
#### Conditional Judgement ####
# Returns 1 if the input parameter is empty or 0, otherwise returns 0
var $bool_var not str;

# Returns 1 if all input parameters are non-empty and not 0, otherwise returns 0
var $bool_var and str1 str2...; 

# Returns 1 if any input parameter is non-empty and not 0, otherwise returns 0
var $bool_var or str1 str2...; 


#### String Judgement ####
# Checks if the string is empty, returns 1 or 0
var $bool_var if_empty str;

# Checks if the string is non-empty, returns 1 or 0
var $bool_var if_not_empty str;

# Checks if the string is a number, returns 1 or 0
var $bool_var if_is_num str;

# Checks if the strings are equal, returns 1 or 0
var $bool_var if_str_eq [-i] str1 str2;

# Checks if the strings are not equal, returns 1 or 0
var $bool_var if_str_ne [-i] str1 str2;

# Checks if the string has the specified prefix, returns 1 or 0
var $bool_var if_starts_with [-i] str prefix;

# Checks if the string has the specified suffix, returns 1 or 0
var $bool_var if_ends_with [-i] str suffix;

# Checks if the substring is present, returns 1 or 0
var $bool_var if_find [-i] str sub_str;

# Checks if the str1 is one of str2 .. strn, returns 1 or 0
var $bool_var if_str_in [-i] str1 str2 str3 .. strn;

#### General String Operations ####
# Copy the value of the variable
var $new_var copy src_str;

# Length of the string
var $new_var len src_str;

# Convert to uppercase
var $new_var upper src_str;

# Convert to lowercase
var $new_var lower src_str;

# Trim leading and trailing whitespace characters
var $new_var trim src_str;

# Trim leading whitespace characters
var $new_var ltrim src_str;

# Trim trailing whitespace characters
var $new_var rtrim src_str;

# Reverse the string
var $new_var reverse src_str;

# Get starting position of substring
var $new_var find [-i] src_str sub_str;

# Repeat the string a given number of times
var $new_var repeat src_str times;

# Extract substring
var $new_var substr src_str start [len];

# Replace keyword
var $new_var replace [-i] src_str src dst; 


#### Regex Judgement ####
# Check if regex matches, returns 1 or 0
var $bool_var if_re_match [-i] src_str match_regex;


#### Regex Operations ####
# Capture regex
var $new_var re_capture [-i] src_str capture_regex assign_value;

# Substitute regex
var $new_var re_sub [-i] src_str capture_regex assign_value;

# Global regex substitution
var $new_var re_gsub [-i] src_str capture_regex assign_value;


#### Mathematical Judgement ####
# Check if numbers are equal, returns 1 or 0
var $bool_var if_eq num1 num2;

# Check if numbers are not equal, returns 1 or 0
var $bool_var if_ne num1 num2;

# Check if less than, returns 1 or 0
var $bool_var if_lt num1 num2;

# Check if less than or equal, returns 1 or 0
var $bool_var if_le num1 num2;

# Check if greater than, returns 1 or 0
var $bool_var if_gt num1 num2;

# Check if greater than or equal, returns 1 or 0
var $bool_var if_ge num1 num2;

# Check if is within the start_num-end_num range, return 1 or 0
var $bool_var if_range num start_num-end_num;

# Check if number is one of num2 .. numn, returns 1 or 0
var $bool_var if_in num1 num2 .. numn;

### Mathematical Operations ####
# Absolute value (returns original format without negative sign)
var $new_var abs num;

# Maximum value (returns with original format)
var $new_var max num1 num2;

# Minimum value (returns with original format)
var $new_var min num1 num2;

# Integer addition
var $new_var add int1 int2;

# Integer subtraction
var $new_var sub int1 int2;

# Integer multiplication
var $new_var mul int1 int2;

# Integer division, int2 cannot be 0
var $new_var div int1 int2;

# Integer modulus, int2 cannot be 0
var $new_var mod int1 int2;

# Round to n significant digits
var $new_var round src_num int;

# Floor value, the largest integer less than or equal to the source
var $new_var floor src_num;

# Ceiling value, the smallest integer greater than or equal to the source
var $new_var ceil src_num;

# Random large positive integer
var $new_var rand;

# Random positive integer in specified range
var $new_var rand_range start_int-end_int;


#### Encoding and Decoding ####
# Convert binary to hexadecimal
var $new_var hex_encode src_str;

# Convert hexadecimal to binary
var $new_var hex_decode src_str;

# Decimal to hexadecimal
var $new_var dec_to_hex dec;

# Hexadecimal to decimal
var $new_var hex_to_dec hex;

# Full URI encoding
var $new_var escape_uri src_str;

# Argument encoding
var $new_var escape_args src_str;

# URI component encoding
var $new_var escape_uri_component src_str;

# HTML encoding
var $new_var escape_html src_str;

# URI decoding
var $new_var unescape_uri src_str;

# Base64 encoding
var $new_var base64_encode src_str;

# Base64url encoding
var $new_var base64url_encode src_str;

# Base64 decoding
var $new_var base64_decode src_str;

# Base64url decoding
var $new_var base64url_decode src_str;


#### Cryptographic Hash Calculations ####
# CRC32 encoding (for short string)
var $new_var crc32_short src_str;

# CRC32 encoding (for long string)
var $new_var crc32_long src_str;

# MD5 encoding
var $new_var md5sum src_str;

# SHA1 encoding
var $new_var sha1sum src_str;

# SHA256 encoding
var $new_var sha256sum src_str;

# SHA384 encoding
var $new_var sha384sum src_str;

# SHA512 encoding
var $new_var sha512sum src_str;

# HMAC_SHA1 encryption
var $new_var hmac_sha1 src_str secret;

# HMAC_SHA256 encryption
var $new_var hmac_sha256 src_str secret;

#### Time Range Judgement ####
# Determine if the current time meets the given time range, requires at least one parameter.
# Returns 1 if all conditions are met, otherwise returns 0.
# The day of the week is represented by 1-7, where Sunday is 7, and timezone format is gmt+0800
var $bool_var if_time_range [year=year_range] [month=month_range] [day=day_range] [wday=wday_range(1-7)] [hour=hour_range] [min=min_range] [sec=sec_range] [timezone];


#### Time Format ####
# Convert timestamp to GMT time in specified format (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] date_format;

# Convert timestamp to HTTP time (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] http_time;

# Convert timestamp to cookie time (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] cookie_time;

# Convert timestamp to local time in specified format (current time if timestamp is omitted)
var $new_var local_time [src_ts] date_format;

# Return current timestamp
var $new_var unixtime;

# Convert HTTP time to timestamp
var $new_var unixtime src_http_time http_time;

# Convert specified date to timestamp (return current timestamp if all are omitted)
var $new_var unixtime src_time date_format timezone; 


#### IP range judgment ####
# Determine whether the IP address is within the IP range, if yes, return 1, otherwise return 0
var $bool_var if_ip_range ip_str ip_range_str1 ip_range_str2...;


#### HTTP Information ####
# Get the value of the specified request arg, arg_name can include '-' and is case-insensitive.
var $new_var get_arg argname;

# Get the value of the specified request cookie name, cookie_name can include '-' or '.' and is case-insensitive.
var $new_var get_cookie cookie_name;

# Get the value of the specified upstream Set-Cookie name, cookie_name can include '-' or '.' and is case-insensitive.
var $new_var get_upstream_cookie cookie_name;
```

All parameters except regular expressions can contain variables. However, incorrect parameter values ​​will cause the function calculation result to be empty.

Variables defined with the var directive can be overwritten by directives such as `set` and `auth_request_set`.

The if parameter enables conditional var. var will not be assign a value if the condition evaluates to “0” or an empty string. And it will continue to look for subsequent definitions of this variable.

```nginx
# When request header A is present, the value of the variable is 'have-header-a'
var $new_var copy have-header-a if=$http_a;

# When request header A is not present but request header B is present, the value of the variable is 'have-header-b'
var $new_var copy have-header-b if=$http_b;

# When both request header A and B are not present, the value of the variable is 'not-have-a-or-b'
var $new_var copy not-have-a-or-b;
```

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
