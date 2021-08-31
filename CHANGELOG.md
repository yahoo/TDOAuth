# Changelog

## 1.4.3
- Character escaping logic compliance with RFC 5849 [PR](https://github.com/yahoo/TDOAuth/pull/36)

## 1.4.2
- Fix bug when URL path ends with a trailing slash
- accessToken and accessSecret at optional in the HMAC initializer

## 1.4.1

- Fix modular headers issue

## 1.4.0

- Complete re-write into Swift
- Pure Swift-native APIs
- Support for arbitrary hash algorithm
- No longer makes assumptions about NSURLRequests (doesn't generate them for you)
- Backwards-compatible and optional Objective-C bridging layer
