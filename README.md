# Server Log Analyzer

A tiny, dependency-free Python tool that turns nginx / Apache combined access logs into a readable summary: traffic, errors, top IPs, top paths, 404s, and possible scanning bursts against your own server.

## Usage

```bash
python loganalyzer.py /var/log/nginx/access.log
python loganalyzer.py access.log --top 20
python loganalyzer.py access.log --json > report.json
```

## What it reports

- Total requests + time range covered
- Status-code breakdown (2xx / 3xx / 4xx / 5xx + top codes)
- Top IPs, top paths, top user agents
- Top 404 paths
- 5xx error count + samples
- Requests per hour
- IPs with 20+ 404s flagged as possible scanning (your own server's logs)

## Try it

```bash
python loganalyzer.py sample.log
```

`sample.log` is a small synthetic log with normal traffic, a 500 error, and one IP probing common admin/backup paths — so you can see the suspicious-IP flag in action.

## Requirements

Python 3.8+. No third-party packages.
