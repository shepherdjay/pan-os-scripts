#!/usr/bin/env python
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


def retrieve_run_and_shared(hostname, api_key):
    return running_config, pushed_config


def safeget(dct, *keys):
    for key in keys:
        try:
            dct = dct[key]
        except KeyError:
            return list()
    return dct


def main():
    script_config = Config('config.yml')

    # Retrieve both configurations from firewall

    running_config = retrieve_firewall_configuration(script_config.firewall_hostname,
                                                     script_config.firewall_api_key,
                                                     config='running')
    pushed_config = retrieve_firewall_configuration(script_config.firewall_hostname,
                                                    script_config.firewall_api_key, config='pushed-shared-policy')

    # Store objects from config in separate dictionaries

    address = safeget(pushed_config, 'policy', 'panorama', 'address', 'entry')
    address_groups = safeget(pushed_config, 'policy', 'panorama', 'address-group', 'entry', )
    pre_rulebase = safeget(pushed_config, 'policy', 'panorama', 'pre-rulebase', 'security', 'rules', 'entry')
    device_rulebase = safeget(running_config, 'config', 'devices', 'entry', 'vsys', 'entry', 'rulebase')
    post_rulebase = safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'security', 'rules', 'entry') \
                    + safeget(pushed_config, 'policy', 'panorama', 'post-rulebase', 'default-security-rules', 'rules',
                              'entry')
    print('lol')


if __name__ == '__main__':
    main()
