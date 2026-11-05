"""
VPC networking enumeration for GCP-Hound.

Collects VPC networks, subnets and firewall rules per project and exports
them as inventory nodes attached to their project/network. Network
topology is attack-relevant context (lateral movement, egress control)
but the edges are containment only — no traversable escalation edges are
implied.

Uses Compute Engine v1 (networks.list, subnetworks.aggregatedList,
firewalls.list) — read-only, included in roles/viewer and
roles/iam.securityAuditor. Failures are non-fatal.
"""

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from utils.auth import credentials_for_bootstrap


def collect_networking(creds, projects, args=None):
    """Collect VPC networks, subnets and firewall rules per project.

    Returns (networks, subnets, firewalls) lists:
      network: {name, id, project, autoCreateSubnetworks, mtu, routingMode}
      subnet:  {name, region, network, ipCidrRange, gatewayAddress, project, privateIpGoogleAccess}
      firewall:{name, network, direction, disabled, sourceRanges, allowedSummary, targetTags, project}
    """
    networks, subnets, firewalls = [], [], []
    if not creds or not projects:
        return networks, subnets, firewalls

    try:
        compute = build('compute', 'v1', credentials=credentials_for_bootstrap(creds))
    except Exception as e:
        if args and args.debug:
            print(f"[DEBUG] Networking collector: compute service build failed: {e}")
        return networks, subnets, firewalls

    for project in projects:
        project_id = (project.get('projectId') or '').lower()
        if not project_id:
            continue

        try:
            request = compute.networks().list(project=project_id)
            while request is not None:
                response = request.execute()
                for net in response.get('items', []):
                    networks.append({
                        'name': net.get('name', ''),
                        'id': net.get('id', ''),
                        'project': project_id,
                        'autoCreateSubnetworks': net.get('autoCreateSubnetworks', True),
                        'mtu': net.get('mtu', ''),
                        'routingMode': (net.get('routingConfig') or {}).get('routingMode', ''),
                    })
                request = compute.networks().list_next(request, response)
        except HttpError as e:
            _report(args, 'networks', project_id, e)
        except Exception as e:
            _debug(args, f'networks for {project_id}', e)

        try:
            request = compute.subnetworks().aggregatedList(project=project_id)
            while request is not None:
                response = request.execute()
                for region_scoped, scoped in (response.get('items') or {}).items():
                    for subnet in scoped.get('subnetworks', []):
                        subnets.append({
                            'name': subnet.get('name', ''),
                            'region': subnet.get('region', '').rsplit('/', 1)[-1],
                            'network': subnet.get('network', '').rsplit('/', 1)[-1],
                            'ipCidrRange': subnet.get('ipCidrRange', ''),
                            'gatewayAddress': subnet.get('gatewayAddress', ''),
                            'privateIpGoogleAccess': subnet.get('privateIpGoogleAccess', False),
                            'project': project_id,
                        })
                request = compute.subnetworks().aggregatedList_next(request, response)
        except HttpError as e:
            _report(args, 'subnetworks', project_id, e)
        except Exception as e:
            _debug(args, f'subnetworks for {project_id}', e)

        try:
            request = compute.firewalls().list(project=project_id)
            while request is not None:
                response = request.execute()
                for fw in response.get('items', []):
                    firewalls.append({
                        'name': fw.get('name', ''),
                        'network': fw.get('network', '').rsplit('/', 1)[-1],
                        'direction': fw.get('direction', ''),
                        'disabled': fw.get('disabled', False),
                        'sourceRanges': fw.get('sourceRanges', []),
                        'targetTags': fw.get('targetTags', []),
                        'allowedSummary': _summarize_rules(fw.get('allowed', [])),
                        'project': project_id,
                    })
                request = compute.firewalls().list_next(request, response)
        except HttpError as e:
            _report(args, 'firewalls', project_id, e)
        except Exception as e:
            _debug(args, f'firewalls for {project_id}', e)

    if networks or subnets or firewalls:
        print(f"[+] Networking: {len(networks)} network(s), {len(subnets)} subnet(s), "
              f"{len(firewalls)} firewall rule(s)")

    return networks, subnets, firewalls


def _summarize_rules(allowed):
    """Compact rule summary, e.g. 'tcp:22,443 udp:53'."""
    parts = []
    for rule in allowed or []:
        ip_protocol = rule.get('IPProtocol', '')
        ports = rule.get('ports', [])
        parts.append(f"{ip_protocol}:{','.join(ports)}" if ports else ip_protocol)
    return ' '.join(parts)


def _report(args, resource, project_id, error):
    if args and args.debug:
        print(f"[DEBUG] Networking: {resource} unavailable for {project_id}: {error}")
    elif args and args.verbose and error.resp is not None and error.resp.status == 403:
        print(f"[!] Networking: no access to {resource} in {project_id}")


def _debug(args, label, error):
    if args and args.debug:
        print(f"[DEBUG] Networking: error collecting {label}: {error}")