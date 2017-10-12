from panexport import retrieve_firewall_configuration
import yaml


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
            self.objectlist = yaml.load(stream)


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


def find_objects(firewall_config, object_list):
    return True


def main():
    script_config = Config('config.yml')
    object_list = ObjectList('objectlist.yml')
    master_dictionary = {}
    errors = []
    for firewall in script_config.firewall_hostnames:
        firewall_config = retrieve_firewall_configuration(firewall, script_config.firewall_api_key)
        results = find_objects(firewall_config, object_list)
        master_dictionary, new_errors = merge_dictionaries(master_dictionary, results)
        errors.append(new_errors)
