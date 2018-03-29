import yaml
from netaddr import IPNetwork


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.top_domain = config['top_domain']
        self.firewall_api_key = config['firewall_api_key']
        self.firewall_hostnames = config['firewall_hostnames']
        self.rule_filters = config['rule_filters']


class PaloFirewallConfig:
    def __init__(self, rules=None):
        if rules is None:
            rules = []
        self.rules = rules


class PaloFirewallRule:
    def __init__(self, name, profile_setting=None, to_zone='any', from_zone='any', source=None, destination=None,
                 source_user=None,
                 category=None, application=None, service=None, hip_profiles=None, action=None, description=None,
                 log_end=None, log_setting=None, rule_type=None):
        self.name = name
        self.profile_setting = profile_setting

        pass
