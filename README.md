# Name

`ngx_http_var_module` is a nginx module that dynamically assigns new variables through predefined functions.

# Table of Content

- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Build Module](#build-module)
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
        var $new_var set $scheme://$host$request_uri;
    }
}
```

# Installation

## Prerequisites

To enable JSON extraction functionality (`extract_json` operation), you need to install the cJSON library first:

**Debian/Ubuntu:**
```bash
sudo apt-get install libcjson-dev
```

**CentOS/RHEL:**
```bash
sudo yum install cjson-devel
```

**macOS:**
```bash
brew install cjson
```

**Build from source:**
```bash
git clone https://github.com/DaveGamble/cJSON.git
cd cJSON
mkdir build && cd build
cmake ..
make
sudo make install
```

If cJSON is not installed, the module will still compile successfully but the `extract_json` operation will not be available.

## Build Module

To use this module, configure your nginx branch with `--add-module=/path/to/ngx_http_var_module`.

# Directives

## var

**Syntax:** *var $new_variable function \[-i\] args... \[if\=condition\]*

**Default:** *-*

**Context:** *http, server, location*

Define a new variable whose value is the result of function calculation. The variable value cannot be cached and is recalculated each time it is used.

If the current level does not define a variable with the same variable name, it can be inherited from the previous level.

The `-i` parameter is used to ignore case (Available only in some functions).

Except for the function name, the `-i` parameter, and the regular expression, all parameters are allowed to contain variables.

When the value of a parameter is invalid, the variable's value is empty. In Boolean functions, invalid parameters will also result in an empty value instead of 0.

`var` cannot be used to define the same variable simultaneously with the `map` or `geo` directives. However, the `set` directive can be used to override variables defined by `var`.

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
var $bool_var is_empty str;

# Checks if the string is non-empty, returns 1 or 0
var $bool_var is_not_empty str;

# Checks if the string is a number, returns 1 or 0. Only decimal numbers are allowed. negative numbers and fractions are supported.
var $bool_var is_num str;

# Checks if the strings are equal, returns 1 or 0
var $bool_var str_eq [-i] str1 str2;

# Checks if the strings are not equal, returns 1 or 0
var $bool_var str_ne [-i] str1 str2;

# Checks if the string has the specified prefix, returns 1 or 0
var $bool_var starts_with [-i] str prefix;

# Checks if the string has the specified suffix, returns 1 or 0
var $bool_var ends_with [-i] str suffix;

# Checks if the substring is present, returns 1 or 0
var $bool_var contains [-i] str sub_str;

# Checks if the str1 is one of str2 .. strn, returns 1 or 0
var $bool_var str_in [-i] str1 str2 str3 .. strn;

#### General String Operations ####
# Set the value directly of the variable
var $new_var set src_str;

# Length of the string
var $new_var len src_str;

# Convert to uppercase
var $new_var upper src_str;

# Convert to lowercase
var $new_var lower src_str;

# Capitalize the first letter of each word (words are separated by non-alphanumeric characters)
var $new_var initcap src_str;

# Trim leading and trailing whitespace characters or other characters
var $new_var trim src_str [char];

# Trim leading whitespace characters or other characters
var $new_var ltrim src_str [char];

# Trim trailing whitespace characters or other characters
var $new_var rtrim src_str [char];

# Reverse the string
var $new_var reverse src_str;

# Get starting position of substring
var $new_var position [-i] src_str sub_str;

# Repeat the string a given number of times
var $new_var repeat src_str times;

# Extract substring
var $new_var substr src_str start [len];

# Replace keyword
var $new_var replace [-i] src_str src dst;

# Extract parameters
# Extract a value from a list of parameters. A use case for this is to extract query parameters without having to write a regular expression, but it can be used to look up values in any name/value pair list. If several occurrences of the parameter exist, only the first one is returned. the variable gets a blank value. The delimiter between the name and the value of a parameter is '=' by default, and the parameter separator is '&' by default.
var $new_var extract_param [-i] param_name src_string [separator] [delimiter];

# example: a query "foo=123&bar=456&baz=789". If the parameter name is bar and the Separator is &, then the resulting variable value will be 456.
# var $extraed_arg_bar extract_param bar "foo=123&bar=456&baz=789" & =;

#### JSON operation ####
# Extract json value from a valid json string.
# Requires cJSON library to be installed (see Installation section)
var $new_var extract_json json subkey1 [subkey2] [subkey3] ...;

# Supports nested object keys and array indices [n]
# Returns string values without quotes, other types as JSON strings
# Arrays and objects are returned as compact JSON strings

# Examples:
# Extract from nested object
# var $new_var extract_json '{"a":{"b":{"c":3}}}' a b c;
# Result: 3

# Extract from array using [index]
# var $new_var extract_json '{"users":[{"name":"Alice"},{"name":"Bob"}]}' users [0] name;
# Result: Alice

# Extract array as JSON string
# var $items extract_json '{"data":[1,2,3]}' data;
# Result: [1,2,3]

# Extract object as JSON string
# var $user extract_json '{"user":{"name":"Bob","age":30}}' user;
# Result: {"name":"Bob","age":30}


#### Regex Judgement ####
# Check if regex matches, returns 1 or 0
var $bool_var regex_match [-i] src_str match_regex;


#### Regex Operations ####
# Capture regex
var $new_var regex_capture [-i] src_str regex assign_value;

# Substitute regex
var $new_var regex_sub [-i] src_str regex replacement;


#### Mathematical Judgement ####
# Check if numbers are equal, returns 1 or 0
var $bool_var eq num1 num2;

# Check if numbers are not equal, returns 1 or 0
var $bool_var ne num1 num2;

# Check if less than, returns 1 or 0
var $bool_var lt num1 num2;

# Check if less than or equal, returns 1 or 0
var $bool_var le num1 num2;

# Check if greater than, returns 1 or 0
var $bool_var gt num1 num2;

# Check if greater than or equal, returns 1 or 0
var $bool_var ge num1 num2;

# Check if is within the start_num end_num range, if end_num is not specified, the range is [0, start_num], return 1 or 0
var $bool_var range num start_num [end_num];

# Check if number is one of num2 .. numn, returns 1 or 0
var $bool_var in num1 num2 .. numn;

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

# Bitwise AND operation
var $new_var bitwise_and int1 int2;

# Bitwise NOT operation
var $new_var bitwise_not int;

# Bitwise OR operation
var $new_var bitwise_or int1 int2;

# Bitwise XOR operation (exclusive or)
var $new_var bitwise_xor int1 int2;

# Left shift operation, shift_bits must be >= 0
var $new_var lshift int shift_bits;

# Right shift operation (arithmetic shift, sign bit preserved), shift_bits must be >= 0
var $new_var rshift int shift_bits;

# Unsigned right shift operation (logical shift, zero fill), shift_bits must be >= 0
var $new_var urshift int shift_bits;

# Round to n significant digits
var $new_var round src_num int;

# Truncate decimal part directly (no rounding)
var $new_var int src_num;

# Floor value, the largest integer less than or equal to the source
var $new_var floor src_num;

# Ceiling value, the smallest integer greater than or equal to the source
var $new_var ceil src_num;

# Random positive integer, the range is [start_int, end_int], if end_int is not specified, the range is [0, start_int]
var $new_var rand [start_int] [end_int];

# Random hex sequence in specified. number_of_bytes must be 1-32, default is 32
var $new_var hexrand [number_of_bytes];


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
# CRC32
var $new_var crc32 src_str;

# MD5
var $new_var md5sum src_str;

# SHA1
var $new_var sha1sum src_str;

# SHA224
var $new_var sha224sum src_str;

# SHA256
var $new_var sha256sum src_str;

# SHA384
var $new_var sha384sum src_str;

# SHA512
var $new_var sha512sum src_str;

# HMAC_MD5 encryption
var $new_var hmac_md5 src_str secret;

# HMAC_SHA1 encryption
var $new_var hmac_sha1 src_str secret;

# HMAC_SHA224 encryption
var $new_var hmac_sha224 src_str secret;

# HMAC_SHA256 encryption
var $new_var hmac_sha256 src_str secret;

# HMAC_SHA384 encryption
var $new_var hmac_sha384 src_str secret;

# HMAC_SHA512 encryption
var $new_var hmac_sha512 src_str secret;

#### Time Range Judgement ####
# Determine if the current time meets the given time range, requires at least one parameter.
# Returns 1 if all conditions are met, otherwise returns 0.
# The day of the week is represented by 0-6, where sunday is 0, and timezone format is gmt+0800
var $bool_var time_range [year=year_range] [month=month_range] [day=day_range] [wday=wday_range(0-6)] [hour=hour_range] [min=min_range] [sec=sec_range] [gmt | gmt+0000];


#### Time Format ####
# Convert timestamp to HTTP time (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] http_time;

# Convert timestamp to cookie time (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] cookie_time;

# Convert timestamp to GMT time in specified format (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] date_format;

# Convert timestamp to local time in specified format (current time if timestamp is omitted)
var $new_var local_time [src_ts] date_format;

# Return current timestamp
var $new_var unix_time;

# Convert HTTP time to timestamp
var $new_var unix_time src_time http_time;

# Convert specified date to timestamp (return current timestamp if all are omitted)
var $new_var unix_time src_time date_format [timezone];


#### IP ####
# Determine whether the ip address is within the ip, cidr or ipv4 range, if yes, return 1, otherwise return 0
var $bool_var ip_range ip_str [ipv4 | ipv6 | cidr | ipv4_range ] ...;

# Calculate the network address based on IP address and network bits
# For IPv4: network_bits range is 1-32
# For IPv6: network_bits range is 1-128
# If ipv6_network_bits is not specified, it will use the same value as ipv4_network_bits
# Returns only the network address without the prefix length (e.g., "10.0.0.0" not "10.0.0.0/8")
var $new_var cidr ipv4/ipv6 ipv4_network_bits [ipv6_network_bits];


All parameters except regular expressions can contain variables. However, incorrect parameter values ​​will cause the function calculation result to be empty.

Variables defined with the var directive can be overwritten by directives such as `set` and `auth_request_set`.

The if parameter enables conditional var. var will not be assign a value if the condition evaluates to “0” or an empty string. And it will continue to look for subsequent definitions of this variable.

```nginx
# When request header A is present, the value of the variable is 'have-header-a'
var $new_var set have-header-a if=$http_a;

# When request header A is not present but request header B is present, the value of the variable is 'have-header-b'
var $new_var set have-header-b if=$http_b;

# When both request header A and B are not present, the value of the variable is 'not-have-a-or-b'
var $new_var set not-have-a-or-b;
```

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
