__author__ = 'js201393'

import xlwt
import pan.xapi

panorama_api_key =
dc02_fw01_api_key =


def gather_rules(hostname, api_key):
    cmd_path = '<show><config><pushed-shared-policy></pushed-shared-policy></config></show>'
    firewall = pan.xapi.PanXapi(hostname=hostname,
                                api_key=api_key
                                )
    firewall.op(cmd=cmd_path)
    return firewall.xml_result()


dc02_fw01_rules = gather_rules('dc02-fw01.maverik.com', dc02_fw01_api_key)
print(dc02_fw01_rules)
