import subprocess
from math import ceil
from os.path import basename, splitext
from time import sleep

from benchmark.commands import CommandMaker
from benchmark.config import BenchParameters, ConfigError, LocalCommittee, Key
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError, PathMaker


class LocalBench:
    BASE_PORT = 3000

    def __init__(self, bench_parameters_dict):
        try:
            self.bench_parameters = BenchParameters(bench_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

    def __getattr__(self, attr):
        return getattr(self.bench_parameters, attr)

    def _background_run(self, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'{command} 2> {log_file}'
        subprocess.run(['tmux', 'new', '-d', '-s', name, cmd], check=True)

    def _kill_nodes(self):
        try:
            cmd = CommandMaker.kill()
            subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
        except subprocess.SubprocessError as e:
            raise BenchError('Failed to kill testbed', e)

    def run(self, debug=False):
        assert isinstance(debug, bool)
        Print.heading('Starting local benchmark')

        # Kill any previous testbed.
        self._kill_nodes()

        try:
            Print.info('Setting up testbed...')
            nodes, rate = self.nodes[0], self.rate[0]

            # Cleanup all files.
            cmd = f'{CommandMaker.clean_logs()} ; {CommandMaker.cleanup()}'
            subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
            sleep(0.5)  # Removing the store may take time.

            # Recompile the latest code.
            cmd = CommandMaker.compile(self.witness_only).split()
            subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

            # Create alias for the client and nodes binary.
            cmd = CommandMaker.alias_binaries(
                PathMaker.binary_path(), self.witness_only
            )
            subprocess.run([cmd], shell=True)

            # Generate key files for the witnesses.
            key_files = [PathMaker.key_file(i) for i in range(nodes)]
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
            committee = LocalCommittee(idp, names, self.BASE_PORT)
            committee.print(PathMaker.committee_file())

            # Run the client (it will wait for the witnesses to be ready).
            cmd = CommandMaker.run_client(
                self.witness_only,
                PathMaker.committee_file(),
                rate,
                self.faults,
                idp_key_file,
                self.batch_size,
                debug
            )
            log_file = PathMaker.client_log_file(0, 0)
            self._background_run(cmd, log_file)

            # Run the IdP.
            if not self.witness_only:
                cmd = CommandMaker.run_idp(
                    idp_key_file,
                    PathMaker.committee_file(),
                    PathMaker.idp_secure_db_path(),
                    PathMaker.sync_db_path(),
                    PathMaker.vkd_db_path(),
                    self.batch_size,
                    debug=debug
                )
                log_file = PathMaker.idp_log_file()
                self._background_run(cmd, log_file)

            # Run the shards (except the faulty ones).
            for i in range(len(committee.addresses(self.faults))):
                cmd = CommandMaker.run_witness(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.secure_db_path(i, 0),
                    PathMaker.audit_db_path(i, 0),
                    debug=debug
                )
                log_file = PathMaker.shard_log_file(i, 0)
                self._background_run(cmd, log_file)

            # Wait for all transactions to be processed.
            Print.info(f'Running benchmark ({self.duration} sec)...')
            sleep(self.duration)
            self._kill_nodes()

            # Parse logs and return the parser.
            Print.info('Parsing logs...')
            return LogParser.process(PathMaker.logs_path(), faults=self.faults)

        except (subprocess.SubprocessError, ParseError) as e:
            self._kill_nodes()
            raise BenchError('Failed to run benchmark', e)
