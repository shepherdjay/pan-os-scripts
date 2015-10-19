#!/usr/bin/env python
__author__ = 'js201393'

# noinspection PyPackageRequirements
import pan.xapi
import yaml


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.firewall_hostname = config['firewall_hostname']
        self.firewall_api_key = config['firewall_api_key']


def retrieve_firewall_configuration(hostname, api_key, command=None):
    """

    :param hostname: Hostname (FQDN) of firewall to retreive active configuration form
    :param api_key:  API key to access firewall configuration
    :param command: List of strings where each element is a component of the xpath to retrieve. If this is the empty
    list or none, the full config is returned
    :return:
    """
    if command is None:
        command = []
    firewall = pan.xapi.PanXapi(hostname=hostname, api_key=api_key)

    path = '/' + '/'.join(command)
    firewall.show(path)

    return firewall.xml_result()


def main():
    config = Config('config.yml')
    print(retrieve_firewall_configuration(config.firewall_hostname, config.firewall_api_key))


if __name__ == '__main__':
    main()
