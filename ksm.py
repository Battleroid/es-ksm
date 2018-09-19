import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from getpass import getpass, getuser
from pathlib import Path
from threading import Lock

from decorator import decorator
from elasticsearch import Elasticsearch
from paramiko import AutoAddPolicy, SSHClient


__version__ = '0.1'


@decorator
def opens(method, self, *args, **kwargs):
    self.open()
    return method(self, *args, **kwargs)


@dataclass
class Result:
    """
    Easy access to results of a command.
    """

    out: list
    err: list
    exit_status: int

    def __post_init__(self):
        self.out = list(map(str.rstrip, self.out))
        self.err = list(map(str.rstrip, self.err))


@dataclass
class Node:
    """
    Coupling for ssh + node name.
    """

    full_name: str
    ssh: SSHClient
    version: int
    name: str = field(init=False)

    def __post_init__(self):
        self.lock = Lock()
        self.name = self.full_name.rsplit('-', 1)[0]


class SSH:
    """
    Basic SSH client.
    """

    def __init__(self, host, ssh_kwargs=None):
        self.host = host
        self.ssh_kwargs = ssh_kwargs or {}
        self.client = SSHClient()
        self.client.set_missing_host_key_policy(AutoAddPolicy())
        self.transport = None

    @property
    def is_connected(self):
        """
        Whether or not the connection is open. I'll be honest, I stole this
        from the import Fabric code base, it's nice.
        """
        return self.transport.active if self.transport else False

    def open(self):
        """
        Initiate SSH connection (if not open).
        """
        if self.is_connected:
            return
        self.client.connect(self.host)
        self.transport = self.client.get_transport()

    @opens
    def open_sftp(self):
        """
        Get sftp client.
        """
        return self.client.open_sftp()

    @opens
    def run(self, command):
        """
        Run command.
        """
        _, out, err = self.client.exec_command(command)
        return Result(out.readlines(), err.readlines(), out.channel.recv_exit_status())

    @opens
    def sudo(self, command):
        """
        Run command as root (shove sudo in front of it).
        """
        return self.run(' '.join(('sudo', command)))

    def __close__(self):
        self.client.close()


def keystore_add(node, kv, version=6):
    """
    Add item to keystore. One item is added at a time. Lock must be acquired
    for reusing the same SSH client.
    """
    node.lock.acquire()
    key, value = kv
    val = f'echo "{value}" |'
    var = 'ES_PATH_CONF' if version >= 6 else 'CONF_DIR'
    pre = f'sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}'
    cmd = f'/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore add -x -f {key}'
    result = node.ssh.run(' '.join([val, pre, cmd]))
    node.lock.release()
    return result


def keystore_add_file(node, name, file, version=6):
    """
    Add file to keystore. File must be available for upload.
    """
    node.lock.acquire()

    # Before we can do add-file, we need to upload and move the file to the
    # keystore directory for the node.
    input_file = Path(file)
    sftp = node.ssh.open_sftp()
    sftp.put(input_file.resolve(), input_file.name)
    sftp.close()
    node.ssh.run(f'sudo mv {input_file.name} /etc/elasticsearch/{node.name}/')

    # Oddly enough, it requires this to be abosolute (it appears), despite the
    # fact that it has to be within the same conf directory as the keystore.
    # Who the fuck knows why.
    var = 'ES_PATH_CONF' if version >= 6 else 'CONF_DIR'
    pre = f'sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}'
    cmd = f'/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore add-file -f'
    post = f'{name} /etc/elasticsearch/{node.name}/{input_file.name}'
    result = node.ssh.run(' '.join([pre, cmd, post]))
    node.lock.release()
    post_rm = f'rm -f /etc/elasticsearch/{node.name}/{input_file.name}'
    node.ssh.sudo(post_rm)
    return result


def keystore_remove(node, *kv, version=6):
    """
    Remove items from keystore. Multiple items can be removed at once.
    """
    var = 'ES_PATH_CONF' if version >= 6 else 'CONF_DIR'
    pre = f'sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}'
    cmd = f'/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore remove {" ".join(kv)}'
    return node.ssh.run(' '.join([pre, cmd]))


def keystore_list(node, version=6):
    """
    Return list of keys in keystore.
    """
    var = 'ES_PATH_CONF' if version >= 6 else 'CONF_DIR'
    pre = f'sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}'
    cmd = f'/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore list'
    return node.ssh.sudo(' '.join([pre, cmd]))


def keystore_create(node, version=6):
    """
    Create keystore.
    """
    var = 'ES_PATH_CONF' if version >= 6 else 'CONF_DIR'
    pre = f'sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}'
    cmd = f'/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore create'
    return node.ssh.sudo(' '.join([pre, cmd]))


def ksm(args):
    """
    Find nodes, find keystores, mess with them.
    """

    # Setup
    verb = args.verb.lower()
    input_file = args.input_file
    kv = args.key_value
    if verb == 'add':
        kv_max_len = len(max(kv, key=len))
        kv = [k.split('=', 1) for k in kv]
        for k in kv:
            if len(k) != 2:
                raise SystemExit(f'{k[0]} is not in the form of key=value!')
    if verb == 'add-file':
        kv = kv[0]
    es_host = args.es_host
    es_user = args.es_user
    es_pass = args.es_pass or getpass()
    es_auth = (es_user, es_pass)
    es = Elasticsearch(es_host, use_ssl='https' in es_host, verify_certs=True, http_auth=es_auth, timeout=60)

    if not es.ping():
        raise SystemExit('Cannot authenticate with ES')

    es_version = int(es.info()['version']['number'].replace('.', ''))
    es_major_version = int(str(es_version)[0])
    es_cluster_name = es.info()['cluster_name']

    machines = [Node(n['name'], SSH(n['ip']), es_version) for n in es.cat.nodes(format='json', h='ip,name')]
    max_len = len(max(machines, key=lambda n: len(n.full_name)).full_name)

    print(f'Found cluster "{es_cluster_name}", major version {es_major_version}.x.x, comprised of {len(machines)} nodes')

    # Go to each machine, manipulate keystore
    with ThreadPoolExecutor() as pool:

        futures = {}
        for node in machines:
            if verb == 'create':
                future = pool.submit(keystore_create, node, version=es_major_version)
                futures[future] = node
            if verb == 'add':
                for item in kv:
                    future = pool.submit(keystore_add, node, item, version=es_major_version)
                    futures[future] = (node, item)
            if verb == 'add-file':
                future = pool.submit(keystore_add_file, node, kv, input_file, version=es_major_version)
                futures[future] = node
            if verb == 'remove':
                future = pool.submit(keystore_remove, node, *kv, version=es_major_version)
                futures[future] = node
            if verb == 'list':
                future = pool.submit(keystore_list, node, version=es_major_version)
                futures[future] = node

        for future in as_completed(futures):
            node = futures[future]
            icon = {0: '✔'}

            if verb == 'list':
                try:
                    result = future.result()
                    print(f'{node.full_name}:', end='')
                    if not result.out:
                        print(' (keystore empty)')
                    else:
                        print()
                        for k in result.out:
                            print(f' - {k}')
                except Exception as e:
                    print(e)
            elif verb == 'remove':
                try:
                    result = future.result()
                    if result.out:
                        status = (
                            f'{icon[0]} (nonexistent)'
                            if 'does not exist' in result.out[0]
                            else icon.get(result.exit_status, '✘')
                        )
                    else:
                        status = icon[0]
                    print(f'{node.full_name:{max_len}} {status}', flush=True)
                except Exception as e:
                    print(e)
            elif verb == 'add':
                try:
                    node, item = node
                    item = '='.join(item)
                    result = future.result()
                    status = icon.get(result.exit_status, '✘')
                    print(f'{node.full_name:{max_len}} {item:{kv_max_len}} {status}')
                except Exception as e:
                    print(e)
            elif verb == 'add-file':
                try:
                    result = future.result()
                    status = icon.get(result.exit_status, '✘')
                    print(f'{node.full_name:{max_len}} {status}', flush=True)
                    if result.exit_status != 0:
                        print('\n'.join(result.out))
                except Exception as e:
                    print(e)
            elif verb == 'create':
                try:
                    result = future.result()
                    status = icon.get(result.exit_status, '✘')
                    print(f'{node.full_name:{max_len}} {status}', flush=True)
                    if result.exit_status != 0:
                        print('\n'.join(result.out))
                except Exception as e:
                    print(e)


def main():
    """
    Manage keystores for a given cluster by SSHing to the machines and
    manipulating the nodes themselves. Huge pain in the ass, but easier than
    doing it yourself.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('verb', choices=['add', 'add-file', 'remove', 'list', 'create'])
    parser.add_argument('key_value', nargs='*', help='key (and value if applicable in the form of key=value)')
    parser.add_argument('--input-file', nargs='?', help='file for add-file verb')
    parser.add_argument('--es-host', required=True, help='es api')
    parser.add_argument('--es-user', default=getuser(), help='es user')
    parser.add_argument('--es-pass', help='es pass')
    args = parser.parse_args()
    ksm(args)


if __name__ == '__main__':
    main()
