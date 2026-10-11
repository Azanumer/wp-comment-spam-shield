# Comment Spam Shield

Dependency-free comment spam protection for WordPress — no API keys, no external services, no paid plans.

## How it stops spam

| Layer | What it catches |
|---|---|
| **Honeypot field** | Bots that auto-fill every input reveal themselves instantly |
| **Timing trap** | Comments submitted faster than a human could type (default 5s) |
| **JavaScript challenge** | Server-signed HMAC token that only a real browser can echo back |
| **URL limit** | Comments stuffed with links (default: max 2) |
| **Disposable emails** | Blocks 10 common throwaway-mail domains (filterable) |

All layers are checked in `preprocess_comment` (priority 1), so spam never reaches the database. Blocked attempts are counted per day for 30 days.

## Install

1. Upload the folder to `wp-content/plugins/`
2. Activate **Comment Spam Shield** in Plugins
3. Tune thresholds at **Settings → Spam Shield**

## Hooks

```php
// Override any setting in code:
add_filter( 'css_setting', function( $value, $key ) {
    if ( $key === 'max_urls' ) return 5;
    return $value;
}, 10, 2 );

// Add your own disposable domains:
add_filter( 'css_disposable_domains', function( $domains ) {
    $domains[] = 'spamdomain.example';
    return $domains;
} );
```

## Notes

- `hash_equals()` is used for the challenge comparison (timing-safe).
- The challenge salt is generated once per site and stored in `wp_options` (autoload off).
- Uninstalling deletes all plugin options — nothing is left behind.

## License

MIT
