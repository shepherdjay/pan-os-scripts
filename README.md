## Panorama Firewall Scripts

Script will take a list of firewalls specified in config.yml and pull the combined rulebase for each one.
(This includes pre and post rules if using panorama in your organization)
It will then output it into an excel spreadsheet.

### Quick Start

Install depdendencies:

```
pip install -r requirements.txt
```

Copy `config.yml.example` to `config.yml` and configure the values:

The following values are REQUIRED:
- `firewall_hostnames`: List of firewall hostnames
- `firewall_api_key`: Valid API key for your firewalls. See PaloAlto API Documentation for more information.

The following values are OPTIONAL:
- `top_domain`: Top level domain you would like stripped from filename output. If you would like the output as is leave this value blank.
