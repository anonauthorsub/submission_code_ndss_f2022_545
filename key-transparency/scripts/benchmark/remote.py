from collections import OrderedDict
from fabric import Connection, ThreadingGroup as Group
from fabric.exceptions import GroupException
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from os.path import basename, splitext
from time import sleep
from math import ceil
from copy import deepcopy
import subprocess

from benchmark.config import Committee, Key, BenchParameters, ConfigError
from benchmark.utils import BenchError, Print, PathMaker, progress_bar
from benchmark.commands import CommandMaker
from benchmark.logs import LogParser, ParseError
from benchmark.instance import InstanceManager


class FabricError(Exception):
    ''' Wrapper for Fabric exception with a meaningfull error message. '''

    def __init__(self, error):
        assert isinstance(error, GroupException)
        message = list(error.result.values())[-1]
        super().__init__(message)


class ExecutionError(Exception):
    pass


class Bench:
    def __init__(self, ctx):
        self.manager = InstanceManager.make()
        self.settings = self.manager.settings
        try:
            ctx.connect_kwargs.pkey = RSAKey.from_private_key_file(
                self.manager.settings.key_path
            )
            self.connect = ctx.connect_kwargs
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError('Failed to load SSH key', e)

    def _check_stderr(self, output):
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)

    def install(self):
        Print.info('Installing rust and cloning the repo...')
        cmd = [
            'sudo apt-get update',
            'sudo apt-get -y upgrade',
            'sudo apt-get -y autoremove',

            # The following dependencies prevent the error: [error: linker `cc` not found].
            'sudo apt-get -y install build-essential',
            'sudo apt-get -y install cmake',

            # Required by the vkd package.
            'sudo apt-get -y install pkg-config libssl-dev',

            # Install rust (non-interactive).
            'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
            'source $HOME/.cargo/env',
            'rustup default stable',

            # This is missing from the Rocksdb installer (needed for Rocksdb).
            'sudo apt-get install -y clang',

            # Clone the repo.
            f'(git clone {self.settings.repo_url} || (cd {self.settings.repo_name} ; git pull))'
        ]
        hosts = self.manager.hosts(flat=True)
        try:
            g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
            g.run(' && '.join(cmd), hide=True)
            Print.heading(f'Initialized testbed of {len(hosts)} nodes')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to install repo on testbed', e)

    def kill(self, hosts=[], delete_logs=False):
        assert isinstance(hosts, list)
        assert isinstance(delete_logs, bool)
        hosts = hosts if hosts else self.manager.hosts(flat=True)
        delete_logs = CommandMaker.clean_logs() if delete_logs else 'true'
        cmd = [delete_logs, f'({CommandMaker.kill()} || true)']
        try:
            g = Group(*hosts, user='ubuntu', connect_kwargs=self.connect)
            g.run(' && '.join(cmd), hide=True)
        except GroupException as e:
            raise BenchError('Failed to kill nodes', FabricError(e))

    def _select_hosts(self, bench_parameters):
        nodes = max(bench_parameters.nodes)

        # Ensure there are enough hosts.
        hosts = self.manager.hosts()
        if sum(len(x) for x in hosts.values()) < nodes + 1:
            return []

        # Select the hosts in different data centers.
        ordered = zip(*hosts.values())
        ordered = [x for y in ordered for x in y]
        return ordered[:nodes+1]

    def _background_run(self, host, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'tmux new -d -s "{name}" "{command} |& tee {log_file}"'
        c = Connection(host, user='ubuntu', connect_kwargs=self.connect)
        output = c.run(cmd, hide=True)
        self._check_stderr(output)

    def _update(self, hosts, bench_parameters):
        witness_only = bench_parameters.witness_only
        if bench_parameters.collocate:
            ips = list(set(hosts))
        else:
            ips = list(set([x for y in hosts for x in y]))

        Print.info(
            f'Updating {len(ips)} machines (branch "{self.settings.branch}")...'
        )
        cmd = [
            f'(cd {self.settings.repo_name} && git fetch -f)',
            f'(cd {self.settings.repo_name} && git checkout -f {self.settings.branch})',
            f'(cd {self.settings.repo_name} && git pull -f)',
            'source $HOME/.cargo/env',
            f'(cd {self.settings.repo_name} && {CommandMaker.compile(witness_only)})',
            CommandMaker.alias_binaries(
                f'./{self.settings.repo_name}/target/release/', witness_only
            )
        ]
        g = Group(*ips, user='ubuntu', connect_kwargs=self.connect)
        g.run(' && '.join(cmd), hide=True)

    def _config(self, hosts, bench_parameters):
        Print.info('Generating configuration files...')
        witness_only = bench_parameters.witness_only

        # Cleanup all local configuration files.
        cmd = CommandMaker.cleanup()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        # Recompile the latest code.
        cmd = CommandMaker.compile(witness_only).split()
        subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

        # Create alias for the client and nodes binary.
        cmd = CommandMaker.alias_binaries(
            PathMaker.binary_path(), witness_only
        )
        subprocess.run([cmd], shell=True)

        # Generate witnesses' keys.
        key_files = [PathMaker.key_file(i) for i in range(len(hosts)-1)]
        for key_file in key_files:
            cmd = CommandMaker.generate_key(key_file)
            subprocess.run(cmd.split(), check=True)

        # Generate key file for the IdP.
        idp_key_file = PathMaker.idp_key_file()
        cmd = CommandMaker.generate_key(idp_key_file)
        subprocess.run(cmd.split(), check=True)

        # Generate the committee file.
        idp = Key.from_file(idp_key_file).name
        names = [Key.from_file(x).name for x in key_files]
        idp_address = hosts.pop()
        addresses = OrderedDict((x, y) for x, y in zip(names, hosts))
        committee = Committee(
            idp, idp_address, addresses, self.settings.base_port
        )
        committee.print(PathMaker.committee_file())

        # Cleanup all nodes and upload configuration files.
        names = names[:len(names)-bench_parameters.faults]
        progress = progress_bar(names, prefix='Uploading config files:')
        for i, name in enumerate(progress):
            for ip in committee.ips(name):
                c = Connection(ip, user='ubuntu', connect_kwargs=self.connect)
                c.run(f'{CommandMaker.cleanup()} || true', hide=True)
                c.put(PathMaker.committee_file(), '.')
                c.put(PathMaker.key_file(i), '.')

        # Cleanup the IdP and upload configuration files.
        c = Connection(idp_address, user='ubuntu', connect_kwargs=self.connect)
        c.run(f'{CommandMaker.cleanup()} || true', hide=True)
        c.put(PathMaker.committee_file(), '.')
        c.put(PathMaker.idp_key_file(), '.')

        return committee

    def _run_single(self, rate, committee, bench_parameters, debug=False):
        faults = bench_parameters.faults

        # Kill any potentially unfinished run and delete logs.
        hosts = committee.ips()
        self.kill(hosts=hosts, delete_logs=True)

        # Run the clients (they will wait for the nodes to be ready).
        # Filter all faulty nodes from the client addresses (or they will wait
        # for the faulty nodes to be online).
        Print.info('Booting client...')
        cmd = CommandMaker.run_client(
            bench_parameters.witness_only,
            PathMaker.committee_file(),
            rate,
            bench_parameters.faults,
            PathMaker.idp_key_file(),
            bench_parameters.batch_size,
            debug
        )
        log_file = PathMaker.client_log_file(0, 0)
        host = Committee.ip(committee.idp_address())
        self._background_run(host, cmd, log_file)

        # Run the IdP.
        if not bench_parameters.witness_only:
            cmd = CommandMaker.run_idp(
                PathMaker.idp_key_file(),
                PathMaker.committee_file(),
                PathMaker.idp_secure_db_path(),
                PathMaker.sync_db_path(),
                PathMaker.vkd_db_path(),
                bench_parameters.batch_size,
                debug=debug
            )
            log_file = PathMaker.idp_log_file()
            host = Committee.ip(committee.idp_address())
            self._background_run(host, cmd, log_file)

        # Run the witnesses (except the faulty ones).
        Print.info('Booting witnesses...')
        nodes_addresses = committee.addresses(faults)
        for i, address in enumerate(nodes_addresses):
            cmd = CommandMaker.run_witness(
                PathMaker.key_file(i),
                PathMaker.committee_file(),
                PathMaker.secure_db_path(i, 0),
                PathMaker.audit_db_path(i, 0),
                debug=debug
            )
            log_file = PathMaker.shard_log_file(i, 0)
            host = Committee.ip(address)
            self._background_run(host, cmd, log_file)

        # Wait for all transactions to be processed.
        duration = bench_parameters.duration
        for _ in progress_bar(range(20), prefix=f'Running benchmark ({duration} sec):'):
            sleep(ceil(duration / 20))
        self.kill(hosts=hosts, delete_logs=False)

    def _logs(self, committee, faults, bench_parameters):
        # Delete local logs (if any).
        cmd = CommandMaker.clean_logs()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        # Download witnesses' log files.
        nodes_addresses = committee.addresses(faults)
        progress = progress_bar(
            nodes_addresses, prefix='Downloading witnesses logs:'
        )
        for i, address in enumerate(progress):
            host = Committee.ip(address)
            c = Connection(
                host, user='ubuntu', connect_kwargs=self.connect
            )
            c.get(
                PathMaker.shard_log_file(i, 0),
                local=PathMaker.shard_log_file(i, 0)
            )

        # Download client and IdP log files.
        Print.info('Downloading client log...')
        host = Committee.ip(committee.idp_address())
        c = Connection(
            host, user='ubuntu', connect_kwargs=self.connect
        )
        c.get(
            PathMaker.client_log_file(0, 0),
            local=PathMaker.client_log_file(0, 0)
        )
        if not bench_parameters.witness_only:
            Print.info('Downloading IdP log...')
            c.get(
                PathMaker.idp_log_file(),
                local=PathMaker.idp_log_file()
            )

        # Parse logs and return the parser.
        Print.info('Parsing logs and computing performance...')
        return LogParser.process(PathMaker.logs_path(), faults=faults)

    def run(self, bench_parameters_dict, debug=False):
        assert isinstance(debug, bool)
        Print.heading('Starting remote benchmark')
        try:
            bench_parameters = BenchParameters(bench_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

        # Select which hosts to use.
        selected_hosts = self._select_hosts(bench_parameters)
        if not selected_hosts:
            Print.warn('There are not enough instances available')
            return

        # Update nodes.
        try:
            self._update(selected_hosts, bench_parameters)
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to update nodes', e)

        # Run benchmarks.
        for n in bench_parameters.nodes:
            Print.heading(f'\nBenchmarking {n} nodes')

            # Upload all configuration files.
            try:
                committee = self._config(
                    selected_hosts, bench_parameters
                )
            except (subprocess.SubprocessError, GroupException) as e:
                e = FabricError(e) if isinstance(e, GroupException) else e
                raise BenchError('Failed to configure nodes', e)

            # Remove faulty nodes.
            committee.remove_nodes(committee.size() - n)

            # Run the benchmarks.
            for r in bench_parameters.rate:
                Print.heading(f'\nRunning {n} nodes (input rate: {r:,} tx/s)')
                for i in range(bench_parameters.runs):
                    Print.heading(f'Run {i+1}/{bench_parameters.runs}')
                    try:
                        self._run_single(
                            r, committee, bench_parameters, debug
                        )

                        faults = bench_parameters.faults
                        logger = self._logs(
                            committee, faults, bench_parameters
                        )
                        logger.print(PathMaker.result_file(
                            faults,
                            n,
                            bench_parameters.shards,
                            bench_parameters.collocate,
                            r
                        ))
                    except (subprocess.SubprocessError, GroupException, ParseError) as e:
                        self.kill(hosts=selected_hosts)
                        if isinstance(e, GroupException):
                            e = FabricError(e)
                        Print.error(BenchError('Benchmark failed', e))
                        continue
