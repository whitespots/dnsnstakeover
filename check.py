import socket
import os
import json
from dns import resolver

TIMEOUT=3
dn_hoster_list = {
    'digitalocean': [
        'ns1.digitalocean.com.',
        'ns2.digitalocean.com.',
        'ns3.digitalocean.com.',
    ],
    'hetzner': [
        'helium.ns.hetzner.de.',
        'hydrogen.ns.hetzner.de.',
        'oxygen.ns.hetzner.de.',
        'oxygen.ns.hetzner.de.'
    ],
    'SalesForce': [
        'ns1.exacttarget.com.',
        'ns2.exacttarget.com.',
        'ns3.exacttarget.com.',
        'ns4.exacttarget.com.',
    ]
}


vuln_id = os.environ.get('VULN_ID', 'ns_takeover')
domain = os.environ.get('DOMAIN')


def resp(domain, state=False, possible=False):
    if state:
        if not possible:
            return json.dumps({"vulnerable": "True", "vuln_id": vuln_id, "description": domain})
        else:
            return json.dumps({"vulnerable": "True", "vuln_id": f'{vuln_id}_possible', "description": domain})
    else:
        return json.dumps({"vulnerable": "False", "vuln_id": vuln_id, "description": domain})


def detect_ns(domain):

    custom_resolver = resolver.Resolver(configure=False)

    root_servers = [
        'a.root-servers.net',
        'b.root-servers.net',
        'c.root-servers.net',
        'd.root-servers.net'
    ]

    custom_resolver.nameservers = [socket.gethostbyname(str(ns)) for ns in root_servers]
    answer = custom_resolver.resolve(domain, 'NS', raise_on_no_answer=False)
    secondary_servers = [socket.gethostbyname(str(ns)) for ns in answer.response.authority[0].items]

    last_ns = []
    named_ns_list = []

    for loop in range(0, 5):
        try:
            custom_resolver.nameservers = secondary_servers
            answer = custom_resolver.resolve(domain, 'NS', raise_on_no_answer=False)
            named_ns_list = answer.response.authority[0].items
            secondary_servers = [socket.gethostbyname(str(ns)) for ns in named_ns_list]
        except Exception as ex:
            if any([code in str(ex) for code in ['SERVFAIL', 'REFUSED', 'NXDOMAIN']]):
                last_ns = [str(ns) for ns in named_ns_list]
                break
    return last_ns


def check(domain):
    if not domain:
        return resp(domain=domain, state=False)

    required_error_detected = False
    confident_ns_detected = False

    try:
        resolver.resolve(domain, 'NS')
    except Exception as ex:
        # If someone will see this logic through the exception antipattern, so know - WE NEED TO GREP SERVFAIL somehow..
        if any([code in str(ex) for code in ['SERVFAIL', 'REFUSED']]):
            required_error_detected = True
            last_ns_with_error = detect_ns(domain)
            for provider, servers in dn_hoster_list.items():
                if any([ns in last_ns_with_error for ns in servers]):
                    confident_ns_detected = True
                    break
    if required_error_detected and confident_ns_detected:
        return resp(domain=domain, state=True, possible=False)
    if required_error_detected:
        return resp(domain=domain, state=True, possible=True)
    return resp(domain=domain, state=False)


if __name__ == '__main__':
    print(check(domain))
