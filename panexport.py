#!/usr/bin/env python3

# noinspection PyPackageRequirements
from datetime import datetime

import pan.xapi
import tablib
import xmltodict
import yaml

HEADERS_DEFAULT_MAP = {'rule-type': 'universal', 'negate-source': 'no', 'negate-destination': 'no'}

HEADERS_REMOVE = ['option', 'profile-setting', 'disabled', 'log-end', 'log-start', 'category']

HEADERS_ORDER = ['@name', 'action', 'tag', 'rule-type', 'from', 'source', 'negate-source', 'source-user',
                 'hip-profiles',
                 'to', 'destination', 'negate-destination', 'application', 'service', 'profile-setting', 'description']

__author__ = 'Jay Shepherd'


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.top_domain = config['top_domain']
        self.firewall_api_key = config['firewall_api_key']
        self.firewall_hostnames = config['firewall_hostnames']


def retrieve_firewall_configuration(hostname, api_key, config='running'):
    """
    This takes the FQDN of the firewall and retrieves the requested config.
    Defaults to running.
    :param hostname: Hostname (FQDN) of firewall to retrieve configuration from
    :param api_key:  API key to access firewall configuration
    ;param config: Which config to retrieve, defaults to running.
    :return: Dictionary containing firewall configuration
    """
    firewall = pan.xapi.PanXapi(hostname=hostname, api_key=api_key)
    command = "show config {}".format(config)
    firewall.op(cmd=command, cmd_xml=True)
    return xmltodict.parse(firewall.xml_result())


def combine_the_rulebase(pushed_config, running_config):
    pre_rulebase = safeget(pushed_config, 'policy', 'panorama', 'pre-rulebase', 'security', 'rules', 'entry')
    device_rulebase = safeget(running_config, 'config', 'devices', 'entry', 'vsys', 'entry', 'rulebase', 'entry')
    post_rulebase = safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'security', 'rules', 'entry')
    default_rulebase = safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'default-security-rules', 'rules',
                               'entry')
    # Combine the pre, on-device, and post rule sets into a single ordered view
    combined_rulebase = pre_rulebase + device_rulebase + post_rulebase + default_rulebase
    return combined_rulebase


def safeget(dct, *keys):
    """
    Takes a dictionary and key path. Checks if key exists and returns value of key
    :param dct: Dictionary to iterate over
    :param keys: Keys to iterate over
    :return: Returns value of key as list if it exists, else returns empty list
    """
    dct_as_list = []
    for key in keys:
        try:
            dct = dct[key]
        except (KeyError, TypeError):
            return list()
    if isinstance(dct, list):
        return dct
    else:
        dct_as_list.append(dct)
        return dct_as_list


def get_headers(data_dict, preferred_header_order=None, headers_to_remove=None):
    """
    Takes a nested dictionary and returns headers as a unique list. For PanOS the top level of each dictionary
    database is a entry "ID" field of value xxx. Which then contain additional attributes/keys with values.
    :param data_dict: Dictionary in format correctly
    :param preferred_header_order: List of headers. If one or more headers in this list are found in the provided
    dictionary, they will be returned in the same order they occur in this list. Headers found in the dict but not in
    this list will be sorted and appended to the end of the list.
    :param headers_to_remove: Collection of headers which will not appear in the returned list.
    :return: list of found headers, in an order approximately following the preferred order
    """
    if preferred_header_order is None:
        preferred_header_order = []
    if headers_to_remove is None:
        headers_to_remove = []
    scraped_headers = set()
    for item in data_dict:
        for header in item:
            scraped_headers.add(header)

    ordered_headers = []
    scraped_headers = scraped_headers.difference(set(headers_to_remove))
    for header in preferred_header_order:
        if header in scraped_headers:
            ordered_headers.append(header)
            scraped_headers.remove(header)
    ordered_headers += sorted(list(scraped_headers))
    return ordered_headers


def check_default(object_to_check, default_key, default_map=None):
    """
    Takes a string_to_check, header, and a default_map table. If string is empty and there is
    a default_key mapping returns default.
    :param object_to_check: Python object to check against table, the object type must match the default_key ty
    :param default_key:
    :param default_map:
    :return:
    """
    if object_to_check is '' and default_key in default_map.keys():
        return default_map[default_key]
    return object_to_check


def write_to_excel(rule_list, filename, preferred_header_order=None, headers_to_remove=None, default_map=None):
    # Initialize Tablib Data
    dataset = tablib.Dataset()

    # Define headers we would like to include
    rule_headers = get_headers(rule_list, preferred_header_order, headers_to_remove)
    dataset.headers = ["Order"] + rule_headers

    # Add rules to dataset
    index_num = 0
    for rule in rule_list:
        index_num += 1
        formatted_rule = [index_num]

        for header in rule_headers:
            cell = rule.get(header, '')
            if isinstance(cell, dict):
                cell = cell.get('member', cell)
            if isinstance(cell, list):
                combined_cell = ''
                first_item = True
                for item in cell:
                    if first_item is True:
                        combined_cell += item
                        first_item = False
                    else:
                        combined_cell += ', {}'.format(item)
                formatted_rule.append(combined_cell)
            else:
                safe_cell = check_default(str(cell), header, default_map)
                formatted_rule.append(safe_cell)

        dataset.append(formatted_rule)

    # Use tablib to write rules
    with open(filename, mode='r') as file:
        file.write(dataset.xlsx)


def do_the_things(firewall, api_key, top_domain=''):
    """
    This is the primary meat of the script. It takes a firewall and API key and writes out excel
    sheets with the rulebase.
    :param firewall: Firewall to query
    :param api_key: API key to query
    ;return:
    """
    # "Zhu Li, do the thing!"
    # Retrieve both possible configurations from firewall
    running_config = retrieve_firewall_configuration(firewall,
                                                     api_key,
                                                     config='running')
    pushed_config = retrieve_firewall_configuration(firewall,
                                                    api_key,
                                                    config='pushed-shared-policy')

    # Store objects from config in separate dictionaries.
    # Use helper functions to achieve.
    # Safety First
    address = safeget(pushed_config, 'policy', 'panorama', 'address', 'entry')
    address_groups = safeget(pushed_config, 'policy', 'panorama', 'address-group', 'entry')
    combined_rulebase = combine_the_rulebase(pushed_config, running_config)

    # Define headers we care about being ordered in the order they should be.
    rulebase_headers_order = HEADERS_ORDER

    # I'm removing excel columns that I don't want in output based upon stupid stuff.
    # Perhaps I don't care.
    # Perhaps the fields just don't work correctly because PaloAlto output refuses any consistency.
    # Yeah I'm going to go with the latter option.
    rulebase_headers_remove = HEADERS_REMOVE

    # Remember that consistency thing...
    # ... yeah this is to populate the excel fields with known default mappings.
    # This is for fields I do need to be in output.
    rulebase_default_map = HEADERS_DEFAULT_MAP

    # Finally let's write the damn thing

    write_to_excel(
        combined_rulebase,
        get_filename(firewall.strip(top_domain)),
        rulebase_headers_order,
        rulebase_headers_remove,
        rulebase_default_map
    )

    # I should print something to let user know it worked.
    # Dharma says feedback is important for good coding.
    print('{} processed. Please check directory for output files.'.format(firewall))


def get_filename(firewall):
    """
    Generate an excel spreadsheet filename from a firewall name and the current time.
    :param firewall: firewall name
    :return: A filename in the format YYYY-MM-DD-{firewall}-combined-rules.xlsx
    """
    current_time = datetime.now()
    return (
        "{year}-"
        "{month}-"
        "{day}-"
        "{firewall}-combined-rules"
        ".xlsx"
    ).format(
        firewall=firewall,
        year=pad_to_two_digits(current_time.year),
        month=pad_to_two_digits(current_time.month),
        day=pad_to_two_digits(current_time.day),
    )


def pad_to_two_digits(n):
    """
    Add leading zeros to format a number as at least two digits
    :param n: any number
    :return: The number as a string with at least two digits
    """
    return str(n).zfill(2)


def main():
    script_config = Config('config.yml')
    for firewall in script_config.firewall_hostnames:
        do_the_things(firewall,
                      script_config.firewall_api_key,
                      script_config.top_domain)


if __name__ == '__main__':
    main()
