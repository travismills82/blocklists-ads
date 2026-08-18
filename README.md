# Pi-hole blocklists

Centralized blocklist repository for Pi-hole.

## Combined master list

Use this URL as a Pi-hole adlist:

- https://raw.githubusercontent.com/travismills82/blocklists-ads/main/ads.txt

`ads.txt` is rebuilt automatically every 12 hours from the configured upstream sources plus the repository-local Smart TV exact-domain list.

The generated list targets Pi-hole v6+ and may contain both:

- normalized exact domains
- simple Pi-hole-supported ABP DNS rules such as `||example.com^`

Browser cosmetic rules, exception/allow rules, JavaScript filters, and the repository's Pi-hole regex file are intentionally not merged into `ads.txt`.

## Upstream sources

The source URLs are maintained in [`sources.txt`](sources.txt). The automated builder currently merges:

- StevenBlack hosts
- Froggeric NoAppleAds DNS-relevant rules
- OISD Big
- abuse.ch URLhaus hostfile
- Phishing Army Extended
- HaGeZi Pro
- HaGeZi Threat Intelligence Feed Medium

Each upstream project remains subject to its own license and terms of use.

## Automatic updates

GitHub Actions runs `.github/workflows/update-blocklist.yml` every 12 hours and can also be started manually with **Run workflow**.

The builder:

1. downloads every configured source with retries
2. parses hosts, plain-domain, wildcard, and DNS-oriented ABP formats
3. ignores cosmetic/browser-only and allow rules
4. merges `pihole/smart-tv-strict-blocklist.txt`
5. normalizes and deduplicates domains
6. removes exact/child rules already covered by a parent `||domain^` rule
7. validates a minimum final rule count
8. refuses to create an `ads.txt` approaching GitHub's normal 100 MiB single-file limit
9. commits only when the generated list actually changes

## Smart TV local rules

The repository-local exact-host list is:

- https://raw.githubusercontent.com/travismills82/blocklists-ads/main/pihole/smart-tv-strict-blocklist.txt

Those exact entries are automatically included in the combined `ads.txt` build.

## Regex rules

Regex entries stay separate because they are Pi-hole rules rather than ordinary adlist entries:

- https://raw.githubusercontent.com/travismills82/blocklists-ads/main/pihole/smart-tv-strict-regex.txt

Keep those rules configured separately in Pi-hole. They are not inserted into `ads.txt`.
