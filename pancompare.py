#!/usr/bin/env python3

# noinspection PyPackageRequirements

import pan.xapi
import yaml
import xmltodict
from panexport import retrieve_firewall_configuration, combine_the_rulebase
import re

class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.top_domain = config['top_domain']
        self.firewall_api_key = config['firewall_api_key']
        self.firewall_hostnames = config['firewall_hostnames']

def retrieve_dataplane(hostname, api_key):
    """
    This takes the FQDN of the firewall and retrieves the dataplane information.
    :param hostname: Hostname (FQDN) of firewall to retrieve information from
    :param api_key:  API key to access firewall configuration
    :return: Dictionary containing dataplane
    """
    firewall = pan.xapi.PanXapi(hostname=hostname, api_key=api_key)
    command = "show running security-policy"
    firewall.op(cmd=command, cmd_xml=True)
    return firewall.xml_result()

def compare_dataplane_to_rules(firewall, api_key):

    # Use previous work in panexport to retrieve configuration and combined rulebase
    running_config = retrieve_firewall_configuration(firewall,
                                                     api_key,
                                                     config='running')
    pushed_config = retrieve_firewall_configuration(firewall,
                                                    api_key,
                                                    config='pushed-shared-policy')
    combined_rulebase = combine_the_rulebase(pushed_config, running_config)
    dataplane_raw = retrieve_dataplane(firewall, api_key)

    # Define Regex Matches
    dataplane_regex = re.compile('DP dp0:\n\n(.+)\n\nDP dp1:', re.DOTALL)
    find_rules_regex = re.compile(r"""
        "(.+?)"     # Find Rule Name
        \s          # Skip WhiteSpace
        ({.+?})     # Find Variables in Rule
        """, re.VERBOSE)
    parameters_regex = re.compile(r"""
        (\w+)       # Parameter Name
        \s          # Whitespace
        (.+?)       # Parameter
        ;           # End of Parameter String
        """, re.VERBOSE)

    # Start Regex Parsing
    dataplane_stripped = re.sub('\n','',(dataplane_regex.search(dataplane_raw).group(1)))
    rules = find_rules_regex.findall(dataplane_stripped)
    dataplane_rules = {}
    for rule in rules:
        rule_name = rule[0]
        parameters = dict(parameters_regex.findall(rule[1]))
        dataplane_rules.update({rule_name: parameters})

def main():
    script_config = Config('config.yml')
    for firewall in script_config.firewall_hostnames:
        compare_dataplane_to_rules(firewall, script_config.firewall_api_key)

if __name__ == '__main__':
    main()
