#!/usr/bin/env python3
__author__ = 'Jay Shepherd'

# noinspection PyPackageRequirements
import pan.xapi
import yaml
import xmltodict


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.firewall_hostname = config['firewall_hostname']
        self.firewall_api_key = config['firewall_api_key']


def retrieve_firewall_configuration(hostname, api_key, config='running'):
    """

    :param hostname: Hostname (FQDN) of firewall to retrieve configuration from
    :param api_key:  API key to access firewall configuration
    ;param config: Which config to retrieve, defaults to running.
    :return: Dictionary containing firewall configuration
    """
    firewall = pan.xapi.PanXapi(hostname=hostname, api_key=api_key)
    command = "show config {}".format(config)
    firewall.op(cmd=command, cmd_xml=True)
    return xmltodict.parse(firewall.xml_result())


def safeget(dct, *keys):
    """
    Takes a dictionary and key path. Checks if key exists, if not returns empty list.
    :param dct: Dictionary to iterate over
    :param keys: Keys to iterate over
    :return: Returns dictionary with reference to key if exists, else returns empty list.
    """
    for key in keys:
        try:
            dct = dct[key]
        except (KeyError, TypeError):
            return list()
    return dct


def get_headers(dict, preferred_header_order=[]):
    """
    Takes a nested dictionary and returns headers as a set. For PanOS the top level of each dictionary
    database is a entry "ID" field of value xxx. Which then contain additional attributes/keys with values.
    :param dict: Dictionary in format correctly
    :param preferred_header_order List of headers. If one or more headers in this list are found in the provided
    dictionary, they will be returned in the same order they occur in this list. Headers found in the dict but not in this list
    will be sorted and appended to the end of the list.
    :return: list of found headers, in an order approximately following the preferred order
    """
    scraped_headers = set()
    for rule_id in dict:
        for header in rule_id:
            scraped_headers.add(header)

    ordered_headers = []
    for header in preferred_header_order:
        if header in scraped_headers:
            ordered_headers += header
            scraped_headers.remove(header)
    ordered_headers.append(sorted(list(scraped_headers)))

    return ordered_headers

def main():
    script_config = Config('config.yml')

    # Retrieve both configurations from firewall

    running_config = retrieve_firewall_configuration(script_config.firewall_hostname,
                                                     script_config.firewall_api_key,
                                                     config='running')
    pushed_config = retrieve_firewall_configuration(script_config.firewall_hostname,
                                                    script_config.firewall_api_key,
                                                    config='pushed-shared-policy')

    # Store objects from config in separate dictionaries

    address = safeget(pushed_config, 'policy', 'panorama', 'address', 'entry')
    address_groups = safeget(pushed_config, 'policy', 'panorama', 'address-group', 'entry', )
    pre_rulebase = safeget(pushed_config, 'policy', 'panorama', 'pre-rulebase', 'security', 'rules', 'entry')
    device_rulebase = safeget(running_config, 'config', 'devices', 'entry', 'vsys', 'entry', 'rulebase', 'entry')
    post_rulebase = safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'security', 'rules', 'entry') \
                    + safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'default-security-rules', 'rules',
                              'entry')
    combined_rulebase = pre_rulebase + device_rulebase + post_rulebase


if __name__ == '__main__':
    main()
