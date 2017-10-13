import pan.xapi
import yaml
import xml.etree.ElementTree as ET

XML_PATHDICTIONARY = {
    'addresses': './/*address/entry',
    'address-groups': './/*address-group/entry',
}


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.top_domain = config['top_domain']
        self.firewall_api_key = config['firewall_api_key']
        self.firewall_hostnames = config['firewall_hostnames']


class ObjectList:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            objectlist = yaml.load(stream)
        self.addresses = objectlist['addresses']


def merge_dictionaries(dict1, dict2):
    """
    Takes a list of dictionaries and merges them. If a key is conflicted it is instead added to an error list.
    :param dict1: First dictionary
    :param dict2: Second dictionary
    :return: Merged dictionary plus errors as unique list
    """
    result_dict = {}
    errors = []

    for key, value in dict1.items():
        try:
            if value == dict2[key]:
                key_match = True
            else:
                key_match = False
        except (KeyError, TypeError):
            key_match = None
        if key_match is not None:
            if key_match:
                result_dict[key] = value
            else:
                errors.append(key)
        else:
            result_dict[key] = value

    for key, value in dict2.items():
        try:
            if value == dict1[key]:
                key_match = True
            else:
                key_match = False
        except (KeyError, TypeError):
            key_match = None
        if key_match is not None:
            if key_match:
                result_dict[key] = value
            else:
                errors.append(key)
        else:
            result_dict[key] = value

    return result_dict, list(set(errors))


def find_address_objects(firewall_config, object_list):
    """
    Takes a firewall config and object list. Finds all the objects in the list that might be addresses
    :param firewall_config: Firewall Config as XML
    :param object_list: list of object names
    :param xmlpath: xmlpath to search for
    :return: results as dictionary
    """
    result_dict = {}
    # Convert to xml tree for use:
    config_xml = ET.fromstring(firewall_config)

    # Find address objects
    entries = config_xml.findall(XML_PATHDICTIONARY['addresses'])
    # Add matching addresses to dictionary
    for entry in entries:
        entry_value = ""
        if entry.attrib["name"] in object_list:
            for all_tags in entry:
                if all_tags.tag in ['ip-netmask', 'ip-range', 'fqdn']:
                    entry_value = all_tags.text
            result_dict[entry.attrib["name"]] = entry_value
    return result_dict


def find_address_group_objects(firewall_config, object_list):
    result_dict = {}
    # Convert to element tree for use:
    config_xml = ET.fromstring(firewall_config)
    # Find address group objects
    entries = config_xml.findall(XML_PATHDICTIONARY['address-groups'])
    for entry in entries:
        if entry.attrib["name"] in object_list:
            members = []
            for member in entry[0]:
                members.append(member.text)
            result_dict[entry.attrib["name"]] = members
    # Return Found Objects as Dictionary
    return result_dict


def find_group_and_member(firewall_config, object_list):
    members = {}
    address_groups = find_address_group_objects(firewall_config, object_list)
    for key, values in address_groups.items():
        for value in values:
            members.update(find_address_objects(firewall_config, value))
    return address_groups, members


def retrieve_firewall_configuration_as_xml(hostname, api_key, config='running'):
    """
    This takes the FQDN of the firewall and retrieves the requested config.
    Defaults to running.
    :param hostname: Hostname (FQDN) of firewall to retrieve configuration from
    :param api_key:  API key to access firewall configuration
    ;param config: Which config to retrieve, defaults to running.
    :return: XML
    """
    firewall = pan.xapi.PanXapi(hostname=hostname, api_key=api_key)
    command = "show config {}".format(config)
    firewall.op(cmd=command, cmd_xml=True)
    return firewall.xml_result()


def retrieve_and_merge(firewall, api_key):
    running_config = retrieve_firewall_configuration_as_xml(firewall,
                                                            api_key,
                                                            config='running')
    pushed_config = retrieve_firewall_configuration_as_xml(firewall,
                                                           api_key,
                                                           config='pushed-shared-policy')
    combined_xml = ET.Element('data')
    combined_xml.append(ET.fromstring(running_config))
    combined_xml.append(ET.fromstring(pushed_config))

    return ET.tostring(combined_xml)


def write_output(address_groups, addresses, errors):
    print("Address Groups")
    print(address_groups.items())
    print("\n")
    print("Address Objects")
    print(addresses.items())
    print('\n')
    print('Errors')
    print(errors)
    return True


def do_things(firewall, api_key, object_list):
    # Retrieve Live Configuration
    firewall_config = retrieve_and_merge(firewall, api_key)

    # Check list of objects for address-groups first
    address_groups, addresses = find_group_and_member(firewall_config, object_list)

    # Grab Address objects and update members dictionary
    addresses.update(find_address_objects(firewall_config, object_list))

    return address_groups, addresses


def main():
    script_config = Config('config.yml')
    object_list = ObjectList('objectlist.yml')
    master_address_groups = {}
    master_addresses = {}
    errors = []

    for firewall in script_config.firewall_hostnames:
        address_groups, addresses = do_things(firewall, script_config.firewall_api_key, object_list.addresses)
        # Merge Dictionaries
        master_address_groups, new_errors = merge_dictionaries(master_address_groups, address_groups)
        errors.append(new_errors)
        # Append any errors from merge process
        master_addresses, new_errors = merge_dictionaries(master_addresses, addresses)

    write_output(master_address_groups, master_addresses, errors)


if __name__ == '__main__':
    main()
