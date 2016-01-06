#!/usr/bin/env python3

# noinspection PyPackageRequirements

import re

import netaddr
import pan.xapi
import yaml

from panexport import retrieve_firewall_configuration, combine_the_rulebase


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.top_domain = config['top_domain']
        self.firewall_api_key = config['firewall_api_key']
        self.firewall_hostnames = config['firewall_hostnames']
        self.rule_filters = config['rule_filters']


def retrieve_dataplane(hostname, api_key):
    """
    This takes the FQDN of the firewall and retrieves the dataplane information.
    :param hostname: Hostname (FQDN) of firewall to retrieve information from
    :param api_key:  API key to access firewall configuration
    :return: Dictionary containing dataplane or test unit if Debug is True
    """
    firewall = pan.xapi.PanXapi(hostname=hostname, api_key=api_key)
    command = "show running security-policy"
    firewall.op(cmd=command, cmd_xml=True)
    return firewall.xml_result()



def hex_to_ipv6(hex):
    """
    Takes a 128 bit hexidecimal string and returns that string formatted for IPv6
    :param hex: Any 128 bit hexidecimal passed as string
    :return: String formatted in IPv6
    """
    return ':'.join(hex[i:i + 4] for i in range(0, len(hex), 4))


def map_to_address(ip):
    """
    Takes an ip address as string and turns into netaddr object.
    :param ip: IP Address or Network as string.
    :return: netaddr IPAddress or IPNetwork object
    """
    if '/' in ip:
        return netaddr.IPNetwork(ip)
    return netaddr.IPAddress(ip)

def range_to_set(rangelist):
    """
    Takes a nested list of ip ranges and converts to a netaddr IPSet object.
    :param rangelist: A nested list of ip ranges expressed as strings
    :return: netaddr IPSet
    """
    ipset = netaddr.IPSet()
    for ip_range in rangelist:
        ipset.add(netaddr.IPRange(ip_range[0], ip_range[1]))
    return ipset


def convert_to_ipobject(string):
    """
    Takes a large single string of mixed IP Address types and returns a netaddr.IPSet
    Utilizes several helper and map functions to complete.
    :param string: A string of ip addresses, networks, ranges, hex values.
    :return: An IPSet of extracted IPs
    """
    ip_range_regex = re.compile('([0-9]{1,3}(?:\.[0-9]{1,3}){0,3})-([0-9]{1,3}(?:\.[0-9]{1,3}){0,3})')
    ip_address_regex = re.compile('([0-9]{1,3}(?:\.[0-9]{1,3}){0,3}(?:\/[0-9]+)*)')
    ip_hex_regex = re.compile(r'0x([0-9a-f]+)(\/\d+)')

    if string == 'any':
        return netaddr.IPSet([netaddr.IPNetwork('::/0')])

    # Look for Hexes first, convert them to form netaddr can understand
    hex_addresses = ip_hex_regex.findall(string)
    converted_hex_list = []
    if len(hex_addresses) > 0:
        for address in hex_addresses:
            ipv6 = hex_to_ipv6(address[0]) + address[1]
            converted_hex_list.append(ipv6)
    iphex_objects = list(map(map_to_address, converted_hex_list))
    string = ip_hex_regex.sub('', string)

    # Look for Ranges second and remove from string, also convert them to range objects.
    # This allows us to reduce complexity of the ip address regex.
    # I'm not using a map like the other devices to due a bug in netaddr reported issue 121
    ip_ranges = ip_range_regex.findall(string)
    ipset_ranges = range_to_set(ip_ranges)
    string = ip_range_regex.sub('', string)

    # Find IPAddresses
    ip_addresses = ip_address_regex.findall(string)
    ip_address_objects = list(map(map_to_address, ip_addresses))

    # Combine Both Sets
    ipset_add_hex = netaddr.IPSet(ip_address_objects + iphex_objects)
    return ipset_ranges | ipset_add_hex


def split_multiple_zones(string):
    """
    Takes a string of one or more panos zones and returns a set of zones discovered.
    Compatible with multi-word zones such as "External DMZ"
    :param string: A string of zone(s) in panos dataplane format, ex. '[ Zone1 "Zone 2" ]' or 'Zone1'
    :return: Zones discovered as a set, ex. Set(['Zone1','Zone 2',])
    """
    # Test string if multiple zones
    set_identifier_regex = re.compile(r'\[|\]')
    if set_identifier_regex.search(string):
        multiple_zone = True
    else:
        multiple_zone = False

    # Test if multi-word zone
    multi_identifier_regex = re.compile(r'\"')
    if multi_identifier_regex.search(string):
        multiple_word = True
    else:
        multiple_word = False

    # Now lets logic it
    # Easy
    if not multiple_zone and not multiple_word:
        return string.split()

    # Medium
    elif multiple_zone and not multiple_word:
        return set_identifier_regex.sub('', string).split()
    elif not multiple_zone and multiple_word:
        return multi_identifier_regex.sub('', string)

    # Hard
    elif multiple_word and multiple_zone:
        multi_word_extract_regex = re.compile('(".+?")')
        special_list = multi_word_extract_regex.findall(string)
        for index, zone in enumerate(special_list):
            special_list[index] = multi_identifier_regex.sub('', zone)
        string = multi_word_extract_regex.sub('', string)
        normal_list = set_identifier_regex.sub('', string).split()
        special_list = normal_list + special_list
        return special_list

    # For Debug
    else:
        print("You Screwed Up")


def compare_dataplane_to_rules(firewall, api_key, filters):
    # Use previous work in panexport to retrieve configuration and combined rulebase
    running_config = retrieve_firewall_configuration(firewall,
                                                     api_key,
                                                     config='running')
    pushed_config = retrieve_firewall_configuration(firewall,
                                                    api_key,
                                                    config='pushed-shared-policy')
    combined_rulebase = combine_the_rulebase(pushed_config, running_config)

    # Retrieve the raw dataplane info, debug option allows passing a text file instead to reduce API Calls.
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

    # Strip \n and focus only on first dataplane
    # We are assuming dataplanes match because otherwise you need to call PaloAlto TAC Support
    dataplane_stripped = re.sub('\n', '', (dataplane_regex.search(dataplane_raw).group(1)))

    # Gather the raw_rules including parameters and create empty dictionary
    raw_rules = find_rules_regex.findall(dataplane_stripped)
    dataplane_rules = {}

    # Iterate over the raw_rules to tease out the parameters and store
    # We will also drop any rules in the hard filter list at this time to speed up additional processing
    matched_rulelist = set()
    for rule in raw_rules:
        rule_name = rule[0]
        if rule_name in filters['rule_names']['include']:
            matched_rulelist.add(rule_name)
        elif rule_name in filters['rule_names']['exclude']:
            continue
        else:
            parameters = dict(parameters_regex.findall(rule[1]))
            dataplane_rules.update({rule_name: parameters})

    # Iterate over the zones in each rule to split out multiple zones specified.
    # The iteration/filtering of zones is performed first and separate from ip objects so that
    # we can populate zone filtering matches first. It makes code more complex but saves
    # drastically on time not converting ips on rules that we know match.
    # To avoid runtime errors we actually iterate over a copy of the dictionary.
    cleanup_list = set()
    cleanup_param = set()

    for rule in dataplane_rules:
        for parameter, value in dataplane_rules[rule].items():
            if parameter in ['from', 'to']:
                dataplane_rules[rule][parameter] = split_multiple_zones(value)
                for zone in dataplane_rules[rule][parameter]:
                    if zone in filters['zones']:
                        if (parameter == 'from') and (dataplane_rules[rule]['source'] == 'any'):
                            matched_rulelist.add(rule)
                            cleanup_list.add(rule)
                        elif (parameter == 'to') and (dataplane_rules[rule]['destination'] == 'any'):
                            matched_rulelist.add(rule)
                            cleanup_list.add(rule)
            # While here lets cleanup parameters we aren't filtering on
            elif parameter not in ['source', 'destination']:
                cleanup_param.add((rule, parameter))

    # Cleanup after zone processing.
    for rule, parameter in cleanup_param:
        del dataplane_rules[rule][parameter]
    for rule in cleanup_list:
        del dataplane_rules[rule]
    cleanup_param = set()
    cleanup_list = set()

    # Convert filters to netaddr/network objects
    network_filter = list(map(map_to_address, filters['ip_addresses']))
    ipset_filter = netaddr.IPSet(network_filter)

    # Now that the "easy" rules have been matched we need to iterate over each source/destination
    # turn it into an IP Object for further testing. This is the long part of the script
    for rule in dataplane_rules:
        for parameter, value in dataplane_rules[rule].items():
            if parameter in ['source', 'destination']:
                dataplane_rules[rule][parameter] = convert_to_ipobject(value)
                if ipset_filter & dataplane_rules[rule][parameter]:
                    matched_rulelist.add(rule)
                    break
                else:
                    cleanup_list.add(rule)

    for rule in cleanup_list:
        del dataplane_rules[rule]

    print(firewall)
    for rule in matched_rulelist:
        print(rule)
    print('\n')


def main():
    script_config = Config('config.yml')
    for firewall in script_config.firewall_hostnames:
        compare_dataplane_to_rules(firewall, script_config.firewall_api_key, script_config.rule_filters)


if __name__ == '__main__':
    main()
