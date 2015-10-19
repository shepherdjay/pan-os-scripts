#!/usr/bin/env python
__author__ = 'js201393'

# noinspection PyPackageRequirements
import pan.xapi
import yaml


class Config:
    def __init__(self, filename):
        with open(filename, 'r') as stream:
            config = yaml.load(stream)
        self.firewall_hostname = config["firewall_hostname"]
        self.firewall_api_key = config["firewall_api_key"]


def gather_rules(hostname, api_key):
    cmd_path = '<show><config><pushed-shared-policy></pushed-shared-policy></config></show>'
    firewall = pan.xapi.PanXapi(hostname=hostname, api_key=api_key)
    firewall.op(cmd=cmd_path)
    return firewall.xml_result()


def main():
    config = Config("config.yml")
    print(gather_rules(config.firewall_hostname, config.firewall_api_key))


if __name__ == "__main__":
    main()
