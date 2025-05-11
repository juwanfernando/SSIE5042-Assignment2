'''
Helper for all the execute functions from the execute pages
'''
import subprocess
import re
import ipaddress

def execute_ping(ip_address):
    '''
    A very vulnerable execute script for pinging an ip address
    '''
    if not (validate_ip(ip_address) or validate_domain(ip_address)):
        return ["Invalid IP address or Domain name"]
    output = list()
    #tempoutput = subprocess.check_output("ping -c 4 " + ip_address, shell=True, universal_newlines=True)
    tempoutput = subprocess.run(["ping", "-c", "4", ip_address], capture_output=True, text=True,check=True)
    if tempoutput:
        output = tempoutput.stdout.split('\n')
    return output#.stdout


def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)  # Validates both IPv4 and IPv6
        return True
    except ValueError:
        return False
    
    
def validate_domain(domain):
    pattern = r'^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))
