import argparse
import logging
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from getpass import getpass, getuser
from pathlib import Path
from threading import Lock

from elasticsearch import Elasticsearch

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

log = logging.getLogger("ksm")


@dataclass
class Result:
    """
    Easy access to results of a command.
    """

    out: list
    err: list
    exit_status: int

    def __post_init__(self):
        self.out = list(filter(None, self.out.splitlines()))
        self.err = list(filter(None, self.err.splitlines()))


class SSH:
    """
    Basic SSH client.
    """

    def __init__(self, host):
        self.host = socket.gethostbyaddr(host)[
            0
        ]  # use hostname as the ssh config will differ based on IP vs hostname

    def scp(self, local_src, remote_dest=None, sudo=False):
        """
        SCP file to host, then move if specified.
        """
        log.debug(f"scping {local_src} to {self.host}")
        subprocess.run(
            ["scp", local_src, f"{self.host}:"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if remote_dest:
            log.debug(f"moving file from scp to {remote_dest}")
            cmd = f"mv {local_src.name} {remote_dest}"
            if sudo:
                self.sudo(cmd)
            else:
                self.run(cmd)

    def run(self, command):
        """
        Run command.
        """
        pre = ["ssh", self.host]
        log.debug(f"ssh run: {pre} {command}")
        rv = subprocess.run(
            [*pre, command], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return Result(rv.stdout, rv.stderr, rv.returncode)

    def sudo(self, command):
        """
        Run command as root (shove sudo in front of it).
        """
        log.debug(f"ssh sudo: {command} on {self.host}")
        return self.run(" ".join(("sudo", command)))


@dataclass
class Node:
    """
    Coupling for ssh + node name.
    """

    full_name: str
    ssh: SSH
    version: int
    name: str = field(init=False)

    def __post_init__(self):
        self.lock = Lock()
        self.name = self.full_name.rsplit("-", 1)[0]
        # Uncomment this if for some reason the node is fucked up and has dashes but the dir uses underscores
        # self.name = self.name.replace('-', '_')


def keystore_add(node, kv, version=6):
    """
    Add item to keystore. One item is added at a time. Lock must be acquired
    for reusing the same SSH client.
    """
    log.debug(f"running add on {node}")
    node.lock.acquire()
    key, value = kv
    val = f'echo "{value}" |'
    var = "ES_PATH_CONF" if version >= 6 else "CONF_DIR"
    if version >= 7:
        var = f"JAVA_HOME=/usr/java/default {var}"
    pre = f"sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}"
    cmd = f"/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore add -x -f {key}"
    result = node.ssh.run(" ".join([val, pre, cmd]))
    node.lock.release()
    log.debug(f"add result for {node} {result}")
    return result


def keystore_add_file(node, name, file, version=6):
    """
    Add file to keystore. File must be available for upload.
    """
    log.debug(f"running add-file on {node}")
    node.lock.acquire()

    # Before we can do add-file, we need to upload and move the file to the
    # keystore directory for the node.
    input_file = Path(file)
    node.ssh.scp(input_file.resolve(), f"/etc/elasticsearch/{node.name}/", sudo=True)

    # Oddly enough, it requires this to be absolute (it appears), despite the
    # fact that it has to be within the same conf directory as the keystore.
    # Who the fuck knows why.
    var = "ES_PATH_CONF" if version >= 6 else "CONF_DIR"
    if version >= 7:
        var = f"JAVA_HOME=/usr/java/default {var}"
    pre = f"sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}"
    cmd = (
        f"/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore add-file -f"
    )
    post = f"{name} /etc/elasticsearch/{node.name}/{input_file.name}"
    result = node.ssh.run(" ".join([pre, cmd, post]))
    node.lock.release()
    post_rm = f"rm -f /etc/elasticsearch/{node.name}/{input_file.name}"
    node.ssh.sudo(post_rm)
    log.debug(f"add-file result for {node.name} {result}")
    return result


def keystore_remove(node, *kv, version=6):
    """
    Remove items from keystore. Multiple items can be removed at once.
    """
    log.debug(f"running remove on {node}")
    var = "ES_PATH_CONF" if version >= 6 else "CONF_DIR"
    if version >= 7:
        var = f"JAVA_HOME=/usr/java/default {var}"
    pre = f"sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}"
    cmd = f'/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore remove {" ".join(kv)}'
    result = node.ssh.run(" ".join([pre, cmd]))
    log.debug(f"remove result for {node.name} {result}")
    return result


def keystore_list(node, version=6):
    """
    Return list of keys in keystore.
    """
    log.debug(f"running list on {node}")
    var = "ES_PATH_CONF" if version >= 6 else "CONF_DIR"
    if version >= 7:
        var = f"JAVA_HOME=/usr/java/default {var}"
    pre = f"sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}"
    cmd = f"/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore list"
    result = node.ssh.run(" ".join([pre, cmd]))
    log.debug(f"list result for {node.name} {result}")
    return result


def keystore_create(node, version=6):
    """
    Create keystore.
    """
    log.debug(f"running create on {node}")
    var = "ES_PATH_CONF" if version >= 6 else "CONF_DIR"
    if version >= 7:
        var = f"JAVA_HOME=/usr/java/default {var}"
    pre = f"sudo -u elasticsearch {var}=/etc/elasticsearch/{node.name}"
    cmd = f"/usr/share/elasticsearch{node.version}/bin/elasticsearch-keystore create"
    result = node.ssh.run(" ".join([pre, cmd]))
    log.debug(f"create result for {node.name} {result}")
    return result


def ksm(args):
    """
    Find nodes, find keystores, mess with them.
    """

    # Setup
    verb = args.verb.lower()
    input_file = args.input_file
    kv = args.key_value
    if verb == "add":
        kv_max_len = len(max(kv, key=len))
        kv = [k.split("=", 1) for k in kv]
        for k in kv:
            if len(k) != 2:
                raise SystemExit(f"{k[0]} is not in the form of key=value!")
    if verb == "add-file":
        kv = kv[0]
    es_host = args.es_host
    es_user = args.es_user
    es_pass = args.es_pass or getpass()
    es_auth = (es_user, es_pass)
    es = Elasticsearch(
        es_host,
        use_ssl="https" in es_host,
        verify_certs=True,
        http_auth=es_auth,
        timeout=60,
    )

    if not es.ping():
        raise SystemExit("Cannot authenticate with ES")

    es_version = int(es.info()["version"]["number"].replace(".", ""))
    es_major_version = int(str(es_version)[0])
    es_cluster_name = es.info()["cluster_name"]

    machines = [
        Node(n["name"], SSH(n["ip"]), es_version)
        for n in es.cat.nodes(format="json", h="ip,name")
    ]
    max_len = len(max(machines, key=lambda n: len(n.full_name)).full_name)

    print(
        f'Found cluster "{es_cluster_name}", major version {es_major_version}.x.x, comprised of {len(machines)} nodes'
    )

    # Go to each machine, manipulate keystore
    with ThreadPoolExecutor() as pool:

        futures = {}
        for node in machines:
            if verb == "create":
                future = pool.submit(keystore_create, node, version=es_major_version)
                futures[future] = node
            if verb == "add":
                for item in kv:
                    future = pool.submit(
                        keystore_add, node, item, version=es_major_version
                    )
                    futures[future] = (node, item)
            if verb == "add-file":
                future = pool.submit(
                    keystore_add_file, node, kv, input_file, version=es_major_version
                )
                futures[future] = node
            if verb == "remove":
                future = pool.submit(
                    keystore_remove, node, *kv, version=es_major_version
                )
                futures[future] = node
            if verb == "list":
                future = pool.submit(keystore_list, node, version=es_major_version)
                futures[future] = node
            if verb == "diff":
                future = pool.submit(keystore_list, node, version=es_major_version)
                futures[future] = node

        # Collect differences, only show unique keys per node
        if verb == "diff":
            results = {}
            for future in as_completed(futures):
                node = futures[future]
                result = future.result()
                results[node.full_name] = result.out

            common_items = list(set.intersection(*map(set, results.values())))

            if common_items:
                print(f"Common keys to ALL nodes:")
                for item in sorted(common_items):
                    print(f" - {item}")
                print("\n---\n")

            for node, items in results.items():
                print(f"{node}:", end="")
                if not items:
                    print(" (keystore empty)")
                else:
                    print()
                    if all(k in common_items for k in items):
                        print(f" (keystore contains nothing unique, only common items)")
                    else:
                        for k in sorted(items):
                            if k in common_items:
                                continue
                            print(f" - {k}")
            return

        for future in as_completed(futures):
            node = futures[future]
            icon = {0: "✔"}

            if verb == "list":
                try:
                    result = future.result()
                    print(f"{node.full_name}:", end="")
                    if not result.out:
                        print(" (keystore empty)")
                    else:
                        print()
                        for k in sorted(result.out):
                            print(f" - {k}")
                except Exception as e:
                    print(e)
            elif verb == "remove":
                try:
                    result = future.result()
                    if result.out:
                        status = (
                            f"{icon[0]} (nonexistent)"
                            if "does not exist" in result.out[0]
                            else icon.get(result.exit_status, "✘")
                        )
                    else:
                        status = icon[0]
                    print(f"{node.full_name:{max_len}} {status}", flush=True)
                except Exception as e:
                    print(e)
            elif verb == "add":
                try:
                    node, item = node
                    item = "=".join(item)
                    result = future.result()
                    status = icon.get(result.exit_status, "✘")
                    print(f"{node.full_name:{max_len}} {item:{kv_max_len}} {status}")
                except Exception as e:
                    print(e)
            elif verb == "add-file":
                try:
                    result = future.result()
                    status = icon.get(result.exit_status, "✘")
                    print(f"{node.full_name:{max_len}} {status}", flush=True)
                    if result.exit_status != 0:
                        print("\n".join(result.out))
                except Exception as e:
                    print(e)
            elif verb == "create":
                try:
                    result = future.result()
                    status = icon.get(result.exit_status, "✘")
                    print(f"{node.full_name:{max_len}} {status}", flush=True)
                    if result.exit_status != 0:
                        print("\n".join(result.out))
                except Exception as e:
                    print(e)

        if es_major_version >= 7:
            if verb in ["create", "add", "add-file"]:
                print("Cluster version >= 7, reloading the secure settings endpoint!")
                es.nodes.reload_secure_settings()


def main():
    """
    Manage keystores for a given cluster by SSHing to the machines and
    manipulating the nodes themselves. Huge pain in the ass, but easier than
    doing it yourself.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "verb", choices=["add", "add-file", "remove", "diff", "list", "create"]
    )
    parser.add_argument(
        "key_value",
        nargs="*",
        help="key (and value if applicable in the form of key=value)",
    )
    parser.add_argument(
        "-d", "--debug", default=False, action="store_true", help="enable debug logging"
    )
    parser.add_argument("--input-file", nargs="?", help="file for add-file verb")
    parser.add_argument("--es-host", required=True, help="es api")
    parser.add_argument("-u", "--es-user", default=getuser(), help="es user")
    parser.add_argument("-p", "--es-pass", help="es pass")
    args = parser.parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("debug on")
    ksm(args)


if __name__ == "__main__":
    main()
