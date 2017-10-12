import pan.xapi
import yaml
import xml.etree.ElementTree

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
    config_xml = xml.etree.ElementTree.fromstring(firewall_config)

    # Find address objects
    entries = config_xml.findall(XML_PATHDICTIONARY['addresses'])
    # Add matching addresses to dictionary
    for entry in entries:
        if entry.attrib["name"] in object_list:
            result_dict[entry.attrib["name"]] = entry[0].text

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
    return running_config + pushed_config


def write_output(dictionary, errors):
    print(dictionary.items())
    print(errors)
    return True


def do_things(firewall, api_key, object_list):
    firewall_config = retrieve_and_merge(firewall, api_key)
    results = find_address_objects(firewall_config, object_list)
    return results


def main():
    script_config = Config('config.yml')
    object_list = ObjectList('objectlist.yml')
    master_dictionary = {}
    errors = []
    for firewall in script_config.firewall_hostnames:
        results_for_firewall = do_things(firewall, script_config.firewall_api_key, object_list.addresses)
        master_dictionary, new_errors = merge_dictionaries(master_dictionary, results_for_firewall)
        errors.append(new_errors)
    write_output(master_dictionary, errors)


if __name__ == '__main__':
    main()
