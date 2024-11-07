# ngx_http_var_module

## Name

`ngx_http_var_module` is an nginx module that dynamically assigns new variables through predefined functions.

# Table of Content

- [Name](#name)
- [Status](#status)
- [Features](#features)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
  - [var](#var)
- [Todo](#todo)
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
        var $copy_var copy $scheme://$host$request_uri; # Directly copy the string calculation value
        var $upper_var upper $scheme://$host$request_uri; # The result is converted to upper case
        var $lower_var lower $scheme://$host$request_uri; # The result is converted to lower case
        var $rand_var rand; # Create a random number
        var $re_match_var re_match $request_uri "^/test/(.*)" "$scheme://$host/$1"; # Use regular expression matching and capture $1..$9 into the target string.
        var $re_match_var_i re_match $request_uri "^/TEST/(.*)" "$scheme://$host/$1"; # Similar to re_match, but with case-insensitive matching.
        var $re_sub_var re_sub "hello, a1234" "a([0-9])[0-9]" "[$1]"; # Replace captured part of a string
        var $re_sub_var_i re_sub_i "hello, a1234" "A([0-9])[0-9]" "[$1]"; # Similar to re_sub, but with case-insensitive matching.
        var $re_gsub_var re_gsub "hello, world" "([a-z])[a-z]+" "[$1]"; # Perform global replacement.
        var $re_gsub_var_i re_gsub_i "heLlo, woRld" "([a-z])[a-z]+" "[$1]"; # Similar to re_gsub, but with case-insensitive matching.
        var $max_var max 2 5; # Returns the larger value.
        var $min_var min 2 5; # Returns the smaller value.
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

Variables defined with the var directive can be overwritten by directives such as `set` and `auth_request_set`.

# Todo

Support more operators.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
