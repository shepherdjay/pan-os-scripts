#!/usr/bin/env python3

# noinspection PyPackageRequirements

import re

import netaddr
import pan.xapi
import yaml


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
        return netaddr.IPNetwork(ip).ipv6(True)
    return netaddr.IPAddress(ip).ipv6(True)


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


def split_multiple_zones(zone_string):
    """
    Takes a string of one or more panos zones and returns a set of zones discovered.
    Compatible with multi-word zones such as "External DMZ"
    :param zone_string: A string of zone(s) in panos dataplane format, ex. '[ Zone1 "Zone 2" ]' or 'Zone1'
    :return: Zones discovered as a set, ex. Set(['Zone1','Zone 2',])
    """
    # Test string if multiple zones
    set_identifier_regex = re.compile(r'\[|\]')
    if set_identifier_regex.search(zone_string):
        multiple_zone = True
    else:
        multiple_zone = False

    # Test if multi-word zone
    multi_identifier_regex = re.compile(r'\"')
    if multi_identifier_regex.search(zone_string):
        multiple_word = True
    else:
        multiple_word = False

    # Now lets logic it
    # Easy
    if not multiple_zone and not multiple_word:
        return zone_string.split()

    # Medium
    elif multiple_zone and not multiple_word:
        return set_identifier_regex.sub('', zone_string).split()
    elif not multiple_zone and multiple_word:
        return multi_identifier_regex.sub('', zone_string)

    # Hard
    elif multiple_word and multiple_zone:
        multi_word_extract_regex = re.compile('(".+?")')
        special_list = multi_word_extract_regex.findall(zone_string)
        for index, zone in enumerate(special_list):
            special_list[index] = multi_identifier_regex.sub('', zone)
        zone_string = multi_word_extract_regex.sub('', zone_string)
        normal_list = set_identifier_regex.sub('', zone_string).split()
        special_list = normal_list + special_list
        return special_list

    # For Debug
    else:
        print("You Screwed Up")


def filter_the_things(rule, subkeylist, filterlist):
    """
    Takes a rule dictionary and checks parameters against a subkeylist and filterlist.
    :param rule: Rule as dictionary
    :param subkeylist: List of subkeys or parameters to check.
    :param filterlist: Filterlist
    :return: Matching rules as set
    """
    if isinstance(filterlist, netaddr.IPSet):
        filters = filterlist
        values = netaddr.IPSet()
        for subkey in subkeylist:
            values.update(rule[1][subkey])
    else:
        filters = set(filterlist)
        values = set()
        for subkey in subkeylist:
            if isinstance(rule[1][subkey], list):
                values.update(rule[1][subkey])
            else:
                values.add(rule[1][subkey])
    if filters & values:
        return rule[0]
    return None


def filter_dataplane_rules(dataplane_raw, filters):
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
    # We will also drop any rules in the hard filter list at this time
    matched_rulelist_static = set()
    for rule in raw_rules:
        rule_name = rule[0]
        if rule_name in filters['rule_names']['include']:
            matched_rulelist_static.add(rule_name)
        elif rule_name in filters['rule_names']['exclude']:
            continue
        else:
            parameters = dict(parameters_regex.findall(rule[1]))
            dataplane_rules.update({rule_name: parameters})

    # Iterate over the filterable parameters in each rule to split out into objects we can work with.
    # This includes a list or string of zones and netaddr ip objects for IPs
    for rule in dataplane_rules:
        dataplane_rules[rule]['from'] = split_multiple_zones(dataplane_rules[rule]['from'])
        dataplane_rules[rule]['to'] = split_multiple_zones(dataplane_rules[rule]['to'])
        dataplane_rules[rule]['source'] = convert_to_ipobject(dataplane_rules[rule]['source'])
        dataplane_rules[rule]['destination'] = convert_to_ipobject(dataplane_rules[rule]['destination'])

    matched_rulelist_zone = set()
    for rule in dataplane_rules.items():
        zone_result = filter_the_things(rule, ['from', 'to'], filters['zones'])
        if zone_result is not None:
            matched_rulelist_zone.add(zone_result)

    # Convert filters to netaddr/network objects
    network_filter = list(map(map_to_address, filters['ip_addresses']))
    ipset_filter = netaddr.IPSet(network_filter)

    # Now that the zone rules have been matched we need to iterate over the ip objects.
    matched_rulelist_address = set()
    for rule in dataplane_rules.items():
        address_result = filter_the_things(rule, ['source', 'destination'], ipset_filter)
        if address_result is not None:
            matched_rulelist_address.add(address_result)

    completed_filter = matched_rulelist_address.intersection(matched_rulelist_zone)
    completed_filter.update(matched_rulelist_static)
    return completed_filter

def print_out(firewall,completed_filter):
    print(firewall)
    for rule in completed_filter:
        print(rule)
    print('\n')


def main():
    script_config = Config('config.yml')
    for firewall in script_config.firewall_hostnames:
        dataplane_raw = retrieve_dataplane(firewall, script_config.firewall_api_key)
        completed_filter = filter_dataplane_rules(dataplane_raw, script_config.rule_filters)
        print_out(firewall, completed_filter)


if __name__ == '__main__':
    main()
