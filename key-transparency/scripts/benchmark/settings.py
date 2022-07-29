from json import load, JSONDecodeError
import os

USER_HOME_CMD = "$HOME"
USER_NAME_CMD = "$USER"

class SettingsError(Exception):
    pass


class Settings:
    def __init__(self, testbed, key_name, key_path, base_port, repo_name, repo_url,
                 branch, instance_type, aws_regions):
        inputs_str = [
            testbed, key_name, key_path, repo_name, repo_url, branch, instance_type
        ]
        if isinstance(aws_regions, list):
            regions = aws_regions
        else:
            regions = [aws_regions]
        inputs_str += regions
        ok = all(isinstance(x, str) for x in inputs_str)
        ok &= isinstance(base_port, int)
        ok &= len(regions) > 0
        if not ok:
            raise SettingsError('Invalid settings types')

        self.testbed = testbed

        self.key_name = convert_from_user_specific(key_name)
        self.key_path = convert_from_user_specific(key_path)

        print("Key name: " + self.key_name)
        print("Key path: " + self.key_path)

        self.base_port = base_port

        self.repo_name = repo_name
        self.repo_url = repo_url
        self.branch = branch

        self.instance_type = instance_type
        self.aws_regions = regions

    @classmethod
    def load(cls, filename):
        try:
            with open(filename, 'r') as f:
                data = load(f)

            return cls(
                data['testbed'],
                data['key']['name'],
                data['key']['path'],
                data['port'],
                data['repo']['name'],
                data['repo']['url'],
                data['repo']['branch'],
                data['instances']['type'],
                data['instances']['regions'],
            )
        except (OSError, JSONDecodeError) as e:
            raise SettingsError(str(e))

        except KeyError as e:
            raise SettingsError(f'Malformed settings: missing key {e}')

def convert_from_user_specific(name_or_path):
    cmds_to_replace = [USER_HOME_CMD, USER_NAME_CMD]
    return replace_cmd_with_env(name_or_path, cmds_to_replace)

def replace_cmd_with_env(name_or_path, cmds):
    to_ret = name_or_path
    # Replace each cmd with their env equivalent, e.g., $USER should become eoz.
    for cmd in cmds:
        # Trim $, e.g., $HOME -> HOME
        env = cmd.replace('$', '')
        to_ret = to_ret.replace(cmd, os.environ.get(env))
    return to_ret
