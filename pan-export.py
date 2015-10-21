#!/usr/bin/env python3
__author__ = 'Jay Shepherd'

# noinspection PyPackageRequirements
import pan.xapi
import yaml
import xmltodict
import xlsxwriter


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.firewall_hostname = config['firewall_hostname']
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


def get_headers(dict, preferred_header_order=None, headers_to_remove=None):
    """
    Takes a nested dictionary and returns headers as a unique list. For PanOS the top level of each dictionary
    database is a entry "ID" field of value xxx. Which then contain additional attributes/keys with values.
    :param dict: Dictionary in format correctly
    :param preferred_header_order List of headers. If one or more headers in this list are found in the provided
    dictionary, they will be returned in the same order they occur in this list. Headers found in the dict but not in this list
    will be sorted and appended to the end of the list.
    :return: list of found headers, in an order approximately following the preferred order
    """
    if preferred_header_order is None:
        preferred_header_order = []
    if headers_to_remove is None:
        headers_to_remove = []
    scraped_headers = set()
    for item in dict:
        for header in item:
            scraped_headers.add(header)

    ordered_headers = []
    for header in headers_to_remove:
        if header in scraped_headers:
            scraped_headers.remove(header)
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


def write_to_excel(item_list, filename, preferred_header_order=None, headers_to_remove=None, default_map=None):
    # First get headers for excel sheet from helper function
    headers = get_headers(item_list, preferred_header_order, headers_to_remove)
    # Define workbook
    workbook = xlsxwriter.Workbook(filename)
    worksheet = workbook.add_worksheet()
    excel_row = 0
    excel_col = 0
    # Write Headers
    worksheet.write(0, 0, 'Order')
    for header in headers:
        excel_col += 1
        worksheet.write(excel_row, excel_col, header)
    # Write out rules
    for i in range(0, len(item_list) - 1):
        excel_col = 0
        excel_row = i + 1
        worksheet.write(excel_row, excel_col, excel_row)
        for header in headers:
            excel_col += 1
            cell = item_list[i].get(header, '')
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
                worksheet.write(excel_row, excel_col, combined_cell)
            else:
                safe_cell = check_default(str(cell), header, default_map)
                worksheet.write(excel_row, excel_col, safe_cell)
    workbook.close()


def do_the_things(firewall, api_key):
    """
    This is the primary meat of the script. It takes a firewall and API key and writes out excel
    sheets with the rulebase.
    :param firewall: Firewall to query
    :param api_key: API key to query
    ;return:
    """
    # Retrieve both possible configurations from firewall
    running_config = retrieve_firewall_configuration(firewall,
                                                     api_key,
                                                     config='running')
    pushed_config = retrieve_firewall_configuration(firewall,
                                                    api_key,
                                                    config='pushed-shared-policy')

    # Store objects from config in separate dictionaries.
    # Use helper function to achieve.
    # Safety First
    address = safeget(pushed_config, 'policy', 'panorama', 'address', 'entry')
    address_groups = safeget(pushed_config, 'policy', 'panorama', 'address-group', 'entry', )
    pre_rulebase = safeget(pushed_config, 'policy', 'panorama', 'pre-rulebase', 'security', 'rules', 'entry')
    device_rulebase = safeget(running_config, 'config', 'devices', 'entry', 'vsys', 'entry', 'rulebase', 'entry')
    post_rulebase = safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'security', 'rules', 'entry') \
                    + safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'default-security-rules', 'rules',
                              'entry')

    # Combine the pre, on-device, and post rule sets into a single ordered view
    combined_rulebase = pre_rulebase + device_rulebase + post_rulebase

    # Define headers we care about being ordered in the order they should be.
    rulebase_headers_order = ['@name',
                              'action',
                              'tag',
                              'rule-type',
                              'from',
                              'source',
                              'negate-source',
                              'source-user',
                              'hip-profiles',
                              'to',
                              'destination',
                              'negate-destination',
                              'application',
                              'service',
                              'profile-setting',
                              'description'
                              ]

    # I'm removing excel columns that I don't want in output based upon stupid stuff.
    # Perhaps I don't care.
    # Perhaps the fields just don't work correctly because PaloAlto output refuses any consistency.
    # Yeah I'm going to go with the latter option.
    rulebase_headers_remove = ['option',
                               'profile-setting',
                               'disabled',
                               'log-end',
                               'log-start',
                               'category'
                               ]

    # Remember that consistency thing...
    # ... yeah this is to populate the excel fields with known default mappings.
    # This is for fields I do need to be in output.
    rulebase_default_map = {'rule-type': 'universal',
                            'negate-source': 'no',
                            'negate-destination': 'no',
                            }

    # Finally let's write the damn thing
    write_to_excel(combined_rulebase,
                   '{}-combined-rules.xlsx'.format(firewall),
                   rulebase_headers_order,
                   rulebase_headers_remove,
                   rulebase_default_map
                   )

    # I should print something to let user know it worked.
    # Dharma says feedback is important for good coding.
    print('{} processed. Please check directory for output files.'.format(firewall))

def main():
    script_config = Config('config.yml')
    for firewall in script_config.firewall_hostnames:
        do_the_things(firewall, script_config.firewall_api_key)


if __name__ == '__main__':
    main()
