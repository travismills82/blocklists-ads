# Pi-hole blocklists

Centralized blocklist repository for Pi-hole.

## Usage in Pi-hole

Add these adlists:

- Exact-host blocklist:
  - https://raw.githubusercontent.com/travismills82/blocklists-ads/main/pihole/smart-tv-strict-blocklist.txt

Regex entries are not imported through the regular adlist URL; add them separately:

- Raw regex blocklist:
  - https://raw.githubusercontent.com/travismills82/blocklists-ads/main/pihole/smart-tv-strict-regex.txt

To apply regex entries quickly:

```
# For local Pi-hole shell access
pihole --regexfile https://raw.githubusercontent.com/travismills82/blocklists-ads/main/pihole/smart-tv-strict-regex.txt
```

If `--regexfile` is not available in your Pi-hole version, copy the file contents into `/etc/pihole/regex.list` and run:

```
docker exec pihole pihole reloaddns
```

## Notes

- This is a strict Smart-TV-focused list with broader Pluto/Samsung/LG ad/telemetry coverage.
- Domain entries were validated for your existing Pi-hole configuration.
