# SourceCodester Simple Real Estate Portal System in PHP/OOP 1.0 /index.php?p= Path Traversal (Unauthenticated Local File Inclusion)

## Author

- qwer1230011108

## Vendor Homepage

- https://www.sourcecodester.com/php/15184/simple-real-estate-portal-system-phpoop-free-source-code.html

## Vulnerable File

- /index.php:14-24 (`p` GET parameter)

## VERSION(S)

- 1.0 (current public download, 2026-11)

# PROBLEM TYPE

## Vulnerability Type

- Path Traversal / Unauthenticated Local File Inclusion — CWE-22

## Root Cause

```php
// index.php:14-24
$page = isset($_GET['p']) ? $_GET['p'] : 'home';
if(!file_exists($page.".php") && !is_dir($page)){
    include '404.html';
}else{
    if(is_dir($page))
        include $page.'/index.php';
    else
        include $page.'.php';
}
```

The `p` parameter flows unsanitized into `file_exists()` and `include`. There is no whitelist, no basename normalization and no authentication, so `../` sequences traverse out of the intended page directory and include any existing `.php` file on the filesystem (reachable by the web server user), and any directory's `index.php`.

## Impact

- Unauthenticated inclusion of arbitrary existing PHP files (configuration files, other applications' code under the document root, uploaded PHP artifacts) leading to information disclosure and, when combined with any file-write primitive (e.g. log or upload artifacts), remote code execution.
- Unauthenticated execution of administrative fragments (the amplifier for the SQL injection reported in 01).

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

Local instance `http://127.0.0.1:8159/` (127.0.0.1 only):

```
GET /index.php?p=home
    -> 200, 20561 bytes

GET /index.php?p=../../../workspace/sc15184/reps/home
    -> 200, 20561 bytes   (byte-identical to the canonical path: ../ traversal included the same file from outside the intended directory)
```

Transcript: `poc/F1F3-poc.txt`; screenshot `img/f01f03-poc-output.png`.

# Suggested repair

1. Whitelist routable pages (`$allowed = ['home'=>..., 'about'=>...]`) instead of filesystem-derived inclusion; reject any `p` containing `/`, `\`, or `..`.
2. Place administrative fragments outside the router's reach and require an authenticated bootstrap for them.
3. Serve only from a constrained document root; never include files whose resolved path escapes it (realpath + prefix check).
