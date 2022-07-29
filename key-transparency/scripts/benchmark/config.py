from json import dump, load
from collections import OrderedDict


class ConfigError(Exception):
    pass


class Key:
    def __init__(self, name, secret):
        self.name = name
        self.secret = secret

    @classmethod
    def from_file(cls, filename):
        assert isinstance(filename, str)
        with open(filename, 'r') as f:
            data = load(f)
        return cls(data['name'], data['secret'])


class Committee:
    ''' The committee looks as follows:
        "authorities": {
            "name": {
                "shards": {
                    "0": x.x.x.x:x,
                    ...
                },
            },
            ...
        }
    '''

    def __init__(self, idp, idp_address, witnesses_addresses, base_port):
        ''' The `witnesses_addresses` field looks as follows:
            { 
                "name": "host",
                ...
            }
        '''
        assert isinstance(idp, str)
        assert isinstance(idp_address, str)
        assert isinstance(witnesses_addresses, OrderedDict)
        assert all(isinstance(x, str) for x in witnesses_addresses.keys())
        assert all(isinstance(x, str) for x in witnesses_addresses.values())
        assert isinstance(base_port, int) and base_port > 1024

        self.json = {
            'idp': {
                'name': idp,
                'address': f'{idp_address}:{base_port}'
            },
            'witnesses': OrderedDict()
        }

        port = base_port + 1
        for name, host in witnesses_addresses.items():
            self.json['witnesses'][name] = {
                'voting_power': 1,
                'address': f'{host}:{port}'
            }
            port += 1

    def addresses(self, faults=0):
        ''' Returns an ordered list of list of shards' addresses. '''
        assert faults < self.size()
        addresses = []
        good_nodes = self.size() - faults
        for authority in list(self.json['witnesses'].values())[:good_nodes]:
            addresses += [authority['address']]
        return addresses

    def idp_address(self):
        ''' Returns the network address of the IdP '''
        return self.json['idp']['address']

    def ips(self, name=None):
        ''' Returns all the ips associated with an authority (in any order). '''
        if name is None:
            names = list(self.json['witnesses'].keys())
        else:
            names = [name]

        ips = set()
        for name in names:
            address = self.json['witnesses'][name]['address']
            ips.add(self.ip(address))

        ips.add(self.ip(self.idp_address()))
        return list(ips)

    def remove_nodes(self, nodes):
        ''' remove the `nodes` last nodes from the committee. '''
        assert nodes < self.size()
        for _ in range(nodes):
            self.json['witnesses'].popitem()

    def size(self):
        ''' Returns the number of authorities. '''
        return len(self.json['witnesses'])

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)

    @staticmethod
    def ip(address):
        assert isinstance(address, str)
        return address.split(':')[0]


class LocalCommittee(Committee):
    def __init__(self, idp, names, port):
        assert isinstance(idp, str)
        assert isinstance(names, list)
        assert all(isinstance(x, str) for x in names)
        assert isinstance(port, int)
        idp_address = '127.0.0.1'
        witnesses_addresses = OrderedDict((x, '127.0.0.1') for x in names)
        super().__init__(idp, idp_address, witnesses_addresses, port)


class BenchParameters:
    def __init__(self, json):
        try:
            self.faults = int(json['faults'])

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes or any(x <= 1 for x in nodes):
                raise ConfigError('Missing or invalid number of nodes')
            self.nodes = [int(x) for x in nodes]

            rate = json['rate']
            rate = rate if isinstance(rate, list) else [rate]
            if not rate:
                raise ConfigError('Missing input rate')
            self.rate = [int(x) for x in rate]

            self.batch_size = int(json['batch_size'])

            self.shards = json['shards'] if 'shards' in json else 1

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            self.duration = int(json['duration'])

            if 'witness-only' in json:
                self.witness_only = bool(json['witness-only'])
            else:
                self.witness_only = False

            self.runs = int(json['runs']) if 'runs' in json else 1
        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if min(self.nodes) <= self.faults:
            raise ConfigError('There should be more nodes than faults')


class PlotParameters:
    def __init__(self, json):
        try:
            faults = json['faults']
            faults = faults if isinstance(faults, list) else [faults]
            self.faults = [int(x) for x in faults] if faults else [0]

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes:
                raise ConfigError('Missing number of nodes')
            self.nodes = [int(x) for x in nodes]

            batch_size = json['batch_size']
            batch_size = batch_size if isinstance(batch_size, list) else [batch_size]
            if not batch_size:
                raise ConfigError('Missing batch size')
            self.batch_size = [int(x) for x in batch_size]

            shards = json['shards'] if 'shards' in json else [1]
            shards = shards if isinstance(shards, list) else [shards]
            self.shards = [int(x) for x in shards]

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            max_lat = json['max_latency']
            max_lat = max_lat if isinstance(max_lat, list) else [max_lat]
            if not max_lat:
                raise ConfigError('Missing max latency')
            self.max_latency = [int(x) for x in max_lat]

            if 'y_max' in json:
                self.y_max = int(json['y_max'])
            else:
                self.y_max = None

        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if len(self.nodes) > 1 and len(self.shards) > 1:
            raise ConfigError(
                'Either the "nodes" or the "shards can be a list (not both)'
            )

    def scalability(self):
        return len(self.shards) > 1
