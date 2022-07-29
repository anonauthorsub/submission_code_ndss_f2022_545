from os.path import join

from benchmark.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup():
        return (
            f'rm -r .*-db* ; rm .*.json ; mkdir -p {PathMaker.results_path()}'
        )

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile(witness_only):
        assert isinstance(witness_only, bool)
        feature = 'witness-only-benchmark' if witness_only else 'benchmark'
        return f'cargo build --quiet --release --features {feature}'

    @staticmethod
    def generate_key(key_file):
        assert isinstance(key_file, str)
        return f'./witness generate --filename {key_file}'

    @staticmethod
    def run_witness(keypair, committee, secure_store, audit_storage, debug=False):
        assert isinstance(keypair, str)
        assert isinstance(committee, str)
        assert isinstance(secure_store, str)
        assert isinstance(audit_storage, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (
            f'./witness {v} run --keypair {keypair} --committee {committee} '
            f'--secure_storage {secure_store} --audit_storage {audit_storage}'
        )

    @staticmethod
    def run_idp(keypair, committee, secure_store, sync_storage, vkd_storage, batch_size, debug=False):
        assert isinstance(keypair, str)
        assert isinstance(committee, str)
        assert isinstance(secure_store, str)
        assert isinstance(sync_storage, str)
        assert isinstance(vkd_storage, str)
        assert isinstance(batch_size, int)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (
            f'./idp {v} --keypair {keypair} --committee {committee} '
            f'--secure_storage {secure_store} --sync_storage {sync_storage} '
            f'--vkd_storage {vkd_storage} --batch_size {batch_size}'
        )

    @staticmethod
    def run_client(witness_only, committee, rate, faults, idp=None, proof_entries=None, debug=False):
        assert isinstance(witness_only, bool)
        assert isinstance(committee, str)
        assert isinstance(rate, int)
        assert isinstance(idp, str) or idp is None
        assert isinstance(proof_entries, int) or proof_entries is None
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        if witness_only:
            return (
                f'./witness_client {v} --idp {idp} --rate {rate} --faults {faults} '
                f'--committee {committee} --proof_entries {proof_entries}'
            )
        else:
            return f'./idp_client {v} --rate {rate} --committee {committee} --faults {faults}'

    @staticmethod
    def kill():
        return 'rm -r .*-db* ; tmux kill-server'

    @staticmethod
    def alias_binaries(origin, witness_only):
        assert isinstance(origin, str)
        assert isinstance(witness_only, bool)
        node = join(origin, 'witness')
        if witness_only:
            client = join(origin, 'witness_client')
            return (
                'rm witness ; rm witness_client'
                f'; ln -s {node} . ; ln -s {client} .'
            )
        else:
            client = join(origin, 'idp_client')
            idp = join(origin, 'idp')
            return (
                f'rm witness ; rm idp_client ; rm idp'
                f'; ln -s {node} . ; ln -s {client} . ; ln -s {idp} .'
            )
