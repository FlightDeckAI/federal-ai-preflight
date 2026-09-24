"""Static AX deployment preflight. No cluster access or compliance certification."""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse
import yaml


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f'Duplicate YAML key: {key}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def inspect(text, profile='restricted', internal_hosts=(), known_secrets=()):
    if profile not in ('connected', 'restricted', 'disconnected'):
        raise ValueError('Unknown profile')
    if len(text.encode()) > 2_000_000:
        raise ValueError('Manifest exceeds 2 MB')
    # Aliases are unnecessary here and can conceal cyclic or amplified configuration.
    if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(text)):
        raise ValueError('YAML aliases are unsupported; provide expanded manifests')
    docs = [d for d in yaml.load_all(text, Loader=UniqueLoader) if d is not None]
    if not docs:
        raise ValueError('No manifests supplied')
    findings, resources = [], set()
    for doc in docs:
        if not isinstance(doc, dict) or not isinstance(doc.get('spec'), dict):
            raise ValueError('Each resource needs a mapping spec')
        meta = doc.get('metadata', {})
        identity = (doc.get('kind'), meta.get('atespace', 'default'), meta.get('name'))
        if not identity[2] or identity in resources:
            raise ValueError('Missing or duplicate resource name')
        resources.add(identity)

    def add(doc, code, path, message, level='error'):
        findings.append({'resource': doc['metadata']['name'], 'kind': doc.get('kind', 'missing'),
                         'code': code, 'path': path, 'level': level, 'message': message})

    def external(doc, value, path):
        host = urlparse(value if '://' in value else 'https://' + value).hostname
        if not host or host not in internal_hosts:
            if profile != 'connected':
                add(doc, 'EXTERNAL_DEPENDENCY', path, 'Host is not in the operator-supplied internal-host inventory.')

    for doc in docs:
        kind, spec = doc.get('kind'), doc['spec']
        if doc.get('apiVersion') != 'ax.io/v1alpha1' or kind not in ('Task', 'Workspace', 'Gateway', 'Model'):
            add(doc, 'UNSUPPORTED_RESOURCE', 'apiVersion/kind', 'Only AX v1alpha1 Task, Workspace, Gateway and Model are assessed.')
            continue
        space = doc['metadata'].get('atespace', 'default')
        if kind == 'Task':
            image = spec.get('image', '')
            if not re.search(r'@sha256:[0-9a-f]{64}$', image):
                add(doc, 'UNPINNED_IMAGE', 'spec.image', 'Pin an immutable SHA-256 image digest.')
            external(doc, image.split('/')[0] if '/' in image else 'docker.io', 'spec.image')
            if spec.get('debug') is True:
                add(doc, 'DEBUG_ENABLED', 'spec.debug', 'Debug guest services are enabled.', 'warning')
            for i, item in enumerate(spec.get('env', [])):
                if re.search(r'(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)', item.get('name', ''), re.I) and 'value' in item:
                    add(doc, 'INLINE_CREDENTIAL', f'spec.env[{i}]', 'Credential-like environment name uses a literal value; value is omitted from this report.')
            refs = [('Workspace', x.get('name'), f'spec.workspaces[{i}]') for i, x in enumerate(spec.get('workspaces', []))]
            if 'gateway' in spec:
                refs.append(('Gateway', spec['gateway'].get('name'), 'spec.gateway'))
            for target, name, path in refs:
                if (target, space, name) not in resources:
                    add(doc, 'UNRESOLVED_REFERENCE', path, 'Referenced resource is absent from this manifest bundle.')
        if kind == 'Workspace':
            for i, repo in enumerate(spec.get('git', [])):
                external(doc, repo.get('repo', ''), f'spec.git[{i}].repo')
                if not re.fullmatch(r'[0-9a-f]{40}', repo.get('branch', '')):
                    add(doc, 'MUTABLE_GIT_REF', f'spec.git[{i}].branch', 'Reference is not a full commit hash; verify upstream supports immutable checkout before use.', 'warning')
            for family in ('mcp', 'skills'):
                config = spec.get(family, {})
                if config.get('registries') and profile != 'connected':
                    add(doc, 'REGISTRY_DISCOVERY', f'spec.{family}.registries', 'Dynamic registry discovery needs a separately verified offline mirror.')
                for i, server in enumerate(config.get('servers', [])):
                    external(doc, server.get('endpoint', ''), f'spec.{family}.servers[{i}]')
        if kind == 'Gateway':
            for i, host in enumerate(spec.get('egress', {}).get('allowlist', {}).get('hosts', [])):
                path = f'spec.egress.allowlist.hosts[{i}]'
                if '*' in host.get('host', ''):
                    add(doc, 'WILDCARD_EGRESS', path, 'Wildcard egress prevents a bounded destination review.')
                else:
                    external(doc, host.get('host', ''), path)
        if kind == 'Model':
            if profile == 'disconnected':
                add(doc, 'MODEL_OFFLINE_UNVERIFIED', 'spec.provider', 'AX model provider behavior has not been verified for disconnected operation.')
            secret = spec.get('secretKey', {})
            if secret.get('name') not in known_secrets or not secret.get('key'):
                add(doc, 'SECRET_UNVERIFIED', 'spec.secretKey', 'Secret name/key is incomplete or absent from supplied secret-name inventory.')
    return {'schema_version': 1, 'profile': profile, 'resources_reviewed': len(docs),
            'passed_static_checks': not any(f['level'] == 'error' for f in findings),
            'scope': 'Static review only. No cluster, image, DNS, secret, runtime egress, accreditation or air-gap verification.',
            'findings': findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--profile', choices=['connected', 'restricted', 'disconnected'], default='restricted')
    parser.add_argument('--internal-host', action='append', default=[])
    parser.add_argument('--known-secret', action='append', default=[])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.manifest.read_text(), args.profile, args.internal_host, args.known_secret)
    except (ValueError, TypeError, AttributeError, OSError, yaml.YAMLError) as error:
        parser.exit(2, f'Invalid input: {type(error).__name__}; validate the manifest structure.\n')
    encoded = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end='')
    raise SystemExit(0 if result['passed_static_checks'] else 1)


if __name__ == '__main__':
    main()
