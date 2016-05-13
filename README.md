[![Build Status](https://travis-ci.org/Nuttycomputer/pan-os-scripts.svg?branch=master)](https://travis-ci.org/Nuttycomputer/pan-os-scripts)

## PaloAlto Firewall Scripts

### Quick Start

Install depdendencies:

```
pip install -r requirements.txt
```

Copy `config.yml.example` to `config.yml` and configure the values:

The following values are REQUIRED for all scripts:

- `firewall_hostnames`: List of firewall hostnames
- `firewall_api_key`: Valid API key for your firewalls. See PaloAlto API Documentation for more information.

Additional Optional and Required configurations are including per script below

### pan-export.py

Script will take a list of firewalls specified in config.yml and pull the combined rulebase for each one.
(This includes pre and post rules if using panorama in your organization)
It will then output it into an excel spreadsheet.

The following values in `config.yml` are OPTIONAL for this script:

- `top_domain`: Top level domain you would like stripped from filename output. If you would like the output as is leave this value blank.

### pan-compare.py

Currently DOESN'T Support NEGATE Rules

Script will compare the running dataplane ruleset to a list of custom filters and prints out as a list.
This allows your organization to get rules associated with dynamic objects or dns names according to their actual value.

The following values in `config.yml` are OPTIONAL for this script:

Under `rule_filter`:

  - `zones`: List of Zones to be filtered on. This list is not case-sensitive
  - `ip_addresses`: List of IPs to be filtered on. Must be expressed in CIDR Notation
  - `rule_names`: List of case-sensitive rules to be bypassed during filtering and either included or excluded in the final output. 
  This is in place to speed up the script when checking rules that contain a large numbers of entries (usually a third party dynamic blocklist)
  
Currently the zones filter is an and operation on the ip_addresses list with an implicit "any". 
This means zones will only be returned if the rule exists in that zone and it is accompanied by an IP present in the filter or rule states "any".

###### OPERATION DOESN'T CURRENTLY SUPPORT NEGATE RULES
Meaning the filter will catch rules that negate your filters and exclude rules that should be in your filters.
This is work in progress

It is quick and dirty for my use-case, may expand feature in future as I have time unless Palo beats me to it first.
