# Written by petrascyll
# Thanks to Leotorrez, CaveRabbit, and SilentNightSound for help
# Join AGMG: discord.gg/agmg

import os
import re
import time
import struct
import argparse
import traceback

from dataclasses import dataclass, field
from pathlib import Path

# extra precaution to not 'fix' 
# the same buffer multiple times
global_modified_buffers: dict[str, list[str]] = {}


def main():
    parser = argparse.ArgumentParser(
        prog="ZZZ Fix 1.6",
        description=('')
    )

    parser.add_argument('ini_filepath', nargs='?', default=None, type=str)
    args = parser.parse_args()

    if args.ini_filepath:
        if args.ini_filepath.endswith('.ini'):
            print('Passed .ini file:', args.ini_filepath)
            upgrade_ini(args.ini_filepath)
        else:
            raise Exception('Passed file is not an Ini')

    else:
        # Change the CWD to the directory this script is in
        # Nuitka: "Onefile: Finding files" in https://nuitka.net/doc/user-manual.pdf 
        # I'm not using Nuitka anymore but this distinction (probably) also applies for pyinstaller
        # os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
        print('CWD: {}'.format(os.path.abspath('.')))
        process_folder('.')

    print('Done!')


# SHAMELESSLY (mostly) ripped from genshin fix script
def process_folder(folder_path):
    for filename in os.listdir(folder_path):
        if filename.upper().startswith('DISABLED') and filename.lower().endswith('.ini'):
            continue
        if filename.upper().startswith('DESKTOP'):
            continue

        filepath = os.path.join(folder_path, filename)
        if os.path.isdir(filepath):
            process_folder(filepath)
        elif filename.endswith('.ini'):
            print('Found .ini file:', filepath)
            upgrade_ini(filepath)


def upgrade_ini(filepath):
    try:
        # Errors occuring here is fine as no write operations to the ini nor any buffers are performed
        ini = Ini(filepath).upgrade()
    except Exception as x:
        print('Error occurred: {}'.format(x))
        print('No changes have been applied to {}!'.format(filepath))
        print()
        print(traceback.format_exc())
        print()
        return False

    try:
        # Content of the ini and any modified buffers get written to disk in this function
        # Since the code for this function is more concise and predictable, the chance of it failing
        # is low, but it can happen if Windows doesn't want to cooperate and write for whatever reason.
        ini.save()
    except Exception as X:
        print('Fatal error occurred while saving changes for {}!'.format(filepath))
        print('Its likely that your mod has been corrupted. You must redownload it from the source before attempting to fix it again.')
        print()
        print(traceback.format_exc())
        print()
        return False

    return True


# MARK: Ini
class Ini():
    def __init__(self, filepath):
        self.filepath = filepath
        try:
            self.content  = Path(self.filepath).read_text(encoding='utf-8')
            self.encoding = 'utf-8'
        except UnicodeDecodeError:
            self.content  = Path(self.filepath).read_text(encoding='gb2312')
            self.encoding = 'gb2312'
        

        # The random ordering of sets is annoying
        # Use a list for the hashes that will be iterated on
        # and a set for the hashes I already iterated on
        self._hashes = []
        self._touched = False
        self._done_hashes = set()

        # Only write the modified buffers at the very end after the ini is saved, since
        # the ini can be backed up, while backing up buffers is not not reasonable.
        # Buffer with multiple fixes: will be read from the mod directory for the first
        # fix, and from this dict in memory for subsequent fixes 
        self.modified_buffers = {
            # buffer_filepath: buffer_data
        }

        # Get all (uncommented) hashes in the ini
        pattern = re.compile(r'\n\s*hash\s*=\s*([a-f0-9]*)', flags=re.IGNORECASE)
        self._hashes = pattern.findall(self.content)
    
    def upgrade(self):
        while len(self._hashes) > 0:
            hash = self._hashes.pop()
            if hash not in self._done_hashes:
                if hash in hash_commands:
                    print(f'\tProcessing {hash}:')
                    default_args = DefaultArgs(hash=hash, ini=self, data={}, tabs=2)
                    self.execute(hash_commands[hash], default_args)
                else:
                    print(f'\tSkipping {hash}: No tasks available')
            else:
                print(f'\tSkipping {hash}: Already Checked/Processed')

            self._done_hashes.add(hash)

        return self

    def execute(self, commands, default_args):
        for command in commands:
            clss = command[0]
            args = command[1] if len(command) > 1 else {}
            instance = clss(**args) if type(args) is dict else clss(*args) 
            result: ExecutionResult = instance.execute(default_args)

            self._touched = self._touched or result.touched
            if result.failed:
                print()
                return

            if result.queue_hashes:
                # Only add the hashes that I haven't already iterated on
                self._hashes.extend(set(result.queue_hashes).difference(self._done_hashes))

            if result.queue_commands:
                # sub_default_args = DefaultArgs(
                #     hash = default_args.hash,
                #     ini  = default_args.ini,
                #     data = default_args.data,
                #     tabs = default_args.tabs
                # )
                self.execute(result.queue_commands, default_args)

            if result.signal_break:
                return

        return default_args

    def save(self):
        if self._touched:
            basename = os.path.basename(self.filepath).split('.ini')[0]
            dir_path = os.path.abspath(self.filepath.split(basename+'.ini')[0])
            backup_filename = f'DISABLED_BACKUP_{int(time.time())}.{basename}.ini'
            backup_fullpath = os.path.join(dir_path, backup_filename)

            os.rename(self.filepath, backup_fullpath)
            print(f'Created Backup: {backup_filename} at {dir_path}')
            with open(self.filepath, 'w', encoding=self.encoding) as updated_ini:
                updated_ini.write(self.content)
            # with open('DISABLED_BACKUP_debug.ini', 'w', encoding='utf-8') as updated_ini:
            #     updated_ini.write(self.content)

            if len(self.modified_buffers) > 0:
                print('Writing updated buffers')
                for filepath, data in self.modified_buffers.items():
                    with open(filepath, 'wb') as f:
                        f.write(data)
                    print('\tSaved: {}'.format(filepath))

            print('Updates applied')
        else:
            print('No changes applied')
        print()

    def has_hash(self, hash):
        return (
            (hash in self._hashes)
            or (hash in self._done_hashes)
        )


# MARK: Commands

def get_critical_content(section):
    hash = None
    match_first_index = None
    critical_lines = []
    pattern = re.compile(r'^\s*(.*?)\s*=\s*(.*?)\s*$', flags=re.IGNORECASE)

    for line in section.splitlines():
        line_match = pattern.match(line)
        
        if line.strip().startswith('['):
            continue
        elif line_match and line_match.group(1).lower() == 'hash':
            hash = line_match.group(2)
        elif line_match and line_match.group(1).lower() == 'match_first_index':
            match_first_index = line_match.group(2)
        else:
            critical_lines.append(line)

    return '\n'.join(critical_lines), hash, match_first_index


# Returns all resources used by a commandlist
# Hardcoded to only return vb1 i.e. texcoord resources for now
# (TextureOverride sections are special commandlists)
def process_commandlist(ini_content: str, commandlist: str, target: str):
    line_pattern = re.compile(r'^\s*(run|{})\s*=\s*(.*)\s*$'.format(target), flags=re.IGNORECASE)
    resources = []

    for line in commandlist.splitlines():
        line_match = line_pattern.match(line)
        if not line_match: continue

        if line_match.group(1) == target:
            resources.append(line_match.group(2))

        # Must check the commandlists that are run within the
        # the current commandlist for the resource as well
        # Recursion yay
        elif line_match.group(1) == 'run':
            commandlist_title = line_match.group(2)
            pattern = get_section_title_pattern(commandlist_title)
            commandlist_match = pattern.search(ini_content + '\n[')
            if commandlist_match:
                sub_resources = process_commandlist(ini_content, commandlist_match.group(1), target)
                resources.extend(sub_resources)

    return resources


@dataclass
class DefaultArgs():
    hash : str
    ini  : Ini
    tabs : int
    data : dict[str, str]


@dataclass
class ExecutionResult():
    touched        : bool = False
    failed         : bool = False
    signal_break   : bool = False
    queue_hashes   : tuple[str] = None
    queue_commands : tuple[str] = None


@dataclass(init=False)
class log():
    text: tuple[str]

    def __init__(self, *text):
        self.text = text

    def execute(self, default_args: DefaultArgs):
        tabs        = default_args.tabs

        info  = self.text[0]
        hash  = self.text[1] if len(self.text) > 1 else ''
        title = self.text[2] if len(self.text) > 2 else ''
        rest  = self.text[3:] if len(self.text) > 3 else []

        s = '{}{:34}'.format('\t'*tabs, info)
        if hash  : s += ' - {:8}'.format(hash)
        if title : s += ' - {}'.format(title) 
        if rest  : s += ' - '.join(rest)

        print(s)

        return ExecutionResult(
            touched        = False,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = None
        )


@dataclass
class update_hash():
    new_hash: str

    def execute(self, default_args: DefaultArgs):
        ini         = default_args.ini
        active_hash = default_args.hash

        pattern = re.compile(r'(\n\s*)(hash\s*=\s*{})'.format(active_hash), flags=re.IGNORECASE)
        ini.content, sub_count = pattern.subn(r'\1hash = {}\n; \2'.format(self.new_hash), ini.content)

        default_args.hash = self.new_hash

        return ExecutionResult(
            touched        = True,
            failed         = False,
            signal_break   = False,
            queue_hashes   = (self.new_hash,),
            queue_commands = (
                (log, ('+ Updating {} hash(es) to {}'.format(sub_count, self.new_hash),)),
            )
        )


@dataclass
class comment_sections():

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini
        hash = default_args.hash

        pattern = get_section_hash_pattern(hash)
        new_ini_content = ''   # ini content with all matching sections commented

        prev_j = 0
        commented_count = 0
        section_matches = pattern.finditer(ini.content)
        for section_match in section_matches:
            i, j = section_match.span(1)
            commented_section = '\n'.join(['; ' + line for line in section_match.group(1).splitlines()])
            commented_count  += 1

            new_ini_content += ini.content[prev_j:i] + commented_section
            prev_j = j

        new_ini_content += ini.content[prev_j:]
        
        ini.content = new_ini_content

        return ExecutionResult(
            touched        = True,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = (
                (log, ('- Commented {} relevant section(s)'.format(commented_count),)),
            )
        )


@dataclass
class comment_commandlists():
    commandlist_title: str

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini

        pattern = get_section_title_pattern(self.commandlist_title)
        new_ini_content = ''   # ini content with matching commandlist commented out

        prev_j = 0
        commented_count = 0
        commandlist_matches = pattern.finditer(ini.content)
        for commandlist_match in commandlist_matches:
            i, j = commandlist_match.span(1)
            commented_commandlist = '\n'.join(['; ' + line for line in commandlist_match.group(1).splitlines()])
            commented_count  += 1

            new_ini_content += ini.content[prev_j:i] + commented_commandlist
            prev_j = j

        new_ini_content += ini.content[prev_j:]
        
        ini.content = new_ini_content

        return ExecutionResult(
            touched        = True,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = (
                (log, ('- Commented {} relevant commandlist(s)'.format(commented_count),)),
            )
        )


@dataclass(kw_only=True)
class remove_section():
    capture_content : str = None
    capture_position: str = None

    def execute(self, default_args: DefaultArgs):
        ini         = default_args.ini
        active_hash = default_args.hash
        data        = default_args.data

        pattern = get_section_hash_pattern(active_hash)
        section_match = pattern.search(ini.content)
        if not section_match: raise Exception('Bad regex')
        start, end = section_match.span(1)

        if self.capture_content:
            data[self.capture_content] = get_critical_content(section_match.group(1))[0]
        if self.capture_position:
            data[self.capture_position] = str(start)

        ini.content = ini.content[:start] + ini.content[end:]

        return ExecutionResult(
            touched        = True,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = None
        )


@dataclass(kw_only=True)
class remove_indexed_sections():
    capture_content         : str = None
    capture_indexed_content : str = None
    capture_position        : str = None

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini
        hash = default_args.hash
        data = default_args.data
        
        pattern = get_section_hash_pattern(hash)
        new_ini_content = ''   # ini with ib sections removed
        position        = -1   # First Occurence Deletion Start Position
        prev_end         = 0

        section_matches = pattern.finditer(ini.content)
        for section_match in section_matches:
            if re.search(r'\n\s*match_first_index\s*=', section_match.group(1), flags=re.IGNORECASE):
                if self.capture_indexed_content:
                    critical_content, _, match_first_index = get_critical_content(section_match.group(1))
                    placeholder = '{}{}{}'.format(self.capture_indexed_content, match_first_index, self.capture_indexed_content)
                    data[placeholder] = critical_content
            else:
                if self.capture_content:
                    critical_content = get_critical_content(section_match.group(1))[0]
                    placeholder = self.capture_content
                    data[placeholder] = critical_content

            start, end = section_match.span()
            if position == -1:
                position = start

            new_ini_content += ini.content[prev_end:start]
            prev_end = end

        new_ini_content += ini.content[prev_end:]
        ini.content = new_ini_content

        if self.capture_position:
            data[self.capture_position] = str(position)

        return ExecutionResult(
            touched        = True,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = None
        )


@dataclass(kw_only=True)
class capture_section():
    capture_content  : str = None
    capture_position : str = None

    def execute(self, default_args: DefaultArgs):
        ini         = default_args.ini
        active_hash = default_args.hash
        data        = default_args.data

        pattern = get_section_hash_pattern(active_hash)
        section_match = pattern.search(ini.content)
        if not section_match: raise Exception('Bad regex')
        _, end = section_match.span(1)

        if self.capture_content:
            data[self.capture_content] = get_critical_content(section_match.group(1))[0]
        if self.capture_position:
            data[self.capture_position] = str(end + 1)

        return ExecutionResult(
            touched        = False,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = None
        )


@dataclass(kw_only=True)
class create_new_section():
    section_content  : str
    saved_position   : str = None
    capture_position : str = None

    def execute(self, default_args: DefaultArgs):
        ini         = default_args.ini
        data        = default_args.data

        pos = -1
        if self.saved_position and self.saved_position in data:
            pos = int(data[self.saved_position])

        for placeholder, value in data.items():
            if placeholder.startswith('_'):
                # conditions are not to be used for substitution
                continue
            self.section_content = self.section_content.replace(placeholder, value)

        # Half broken/fixed mods' ini will not have the object indices we're expecting
        # Could also be triggered due to a typo in the hash commands
        for emoji in ['🍰', '🌲', '🤍']:
            if emoji in self.section_content:
                print('Section substitution failed')
                print(self.section_content)
                return ExecutionResult(
                    touched        = False,
                    failed         = True,
                    signal_break   = False,
                    queue_hashes   = None,
                    queue_commands = None
                )
  
        if self.capture_position:
            data[self.capture_position] = str(len(self.section_content) + pos)

        ini.content = ini.content[:pos] + self.section_content + ini.content[pos:]

        return ExecutionResult(
            touched        = True,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = None
        )


@dataclass(kw_only=True)
class transfer_indexed_sections():
    trg_indices: tuple[str] = None
    src_indices: tuple[str] = None

    def execute(self, default_args: DefaultArgs):
        ini         = default_args.ini
        hash        = default_args.hash

        title = None
        p = get_section_hash_pattern(hash)
        ib_matches = p.findall(ini.content)
        indexed_ib_count = 0
        for m in ib_matches:
            if re.search(r'\n\s*match_first_index\s*=', m):
                indexed_ib_count += 1
                if not title: title = re.match(r'^\[TextureOverride(.*?)\]', m, flags=re.IGNORECASE).group(1)[:-1]
            else:
                if not title: title = re.match(r'^\[TextureOverride(.*?)\]', m, flags=re.IGNORECASE).group(1)[:-2]

        if indexed_ib_count == 0:
            return ExecutionResult()

        unindexed_ib_content = '\n'.join([
            f'[TextureOverride{title}IB]',
            f'hash = {hash}',
            '🍰',
            '',
            ''
        ])

        alpha = [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X', 'Y', 'Z'
        ]
        content = ''
        for i, (trg_index, src_index) in enumerate(zip(self.trg_indices, self.src_indices)):
            content += '\n'.join([
                f'[TextureOverride{title}{alpha[i]}]',
                f'hash = {hash}',
                f'match_first_index = {trg_index}',
                f'🤍{src_index}🤍' if src_index != '-1' else 'ib = null',
                '',
                ''
            ])

        return ExecutionResult(
            touched        = False,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = (
                (remove_indexed_sections, {'capture_content': '🍰', 'capture_indexed_content': '🤍', 'capture_position': '🌲'}),
                (create_new_section,      {'saved_position': '🌲', 'section_content': content}),
                (create_new_section,      {'saved_position': '🌲', 'section_content': unindexed_ib_content}),
            ) if indexed_ib_count < len(ib_matches) else (
                (remove_indexed_sections, {'capture_indexed_content': '🤍', 'capture_position': '🌲'}),
                (create_new_section,      {'saved_position': '🌲', 'section_content': content}),
            ),
        )


@dataclass()
class multiply_section_if_missing():
    equiv_hashes: tuple[str] | str
    extra_title : tuple[str]

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini

        if (type(self.equiv_hashes) is not tuple):
            self.equiv_hashes = (self.equiv_hashes,)
        for equiv_hash in self.equiv_hashes:
            if ini.has_hash(equiv_hash):
                return ExecutionResult(
                    touched        = False,
                    failed         = False,
                    signal_break   = False,
                    queue_hashes   = None,
                    queue_commands = (
                        (log, ('/ Skipping Section Multiplication',  f'{equiv_hash}', f'[...{self.extra_title}]',)),
                    ),
                )
        equiv_hash = self.equiv_hashes[0]

        content = '\n'.join([
            '',
            f'[TextureOverride{self.extra_title}]',
            f'hash = {equiv_hash}',
            '🍰',
            '',
        ])

        return ExecutionResult(
            touched        = False,
            failed         = False,
            signal_break   = False,
            queue_hashes   = (equiv_hash,),
            queue_commands = (
                (log,                ('+ Multiplying Section', f'{equiv_hash}', f'[...{self.extra_title}]')),
                (capture_section,    {'capture_content': '🍰', 'capture_position': '🌲'}),
                (create_new_section, {'saved_position': '🌲', 'section_content': content}),
            ),
        )


@dataclass()
class add_ib_check_if_missing():

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini
        hash = default_args.hash
        
        pattern         = get_section_hash_pattern(hash)
        section_matches = pattern.finditer(ini.content)

        needs_check       = False
        new_sections      = ''
        unindexed_section = ''

        for section_match in section_matches:
            if not re.search(r'\n\s*match_first_index\s*=', section_match.group(1), flags=re.IGNORECASE):
                unindexed_section = section_match.group()
                continue

            if re.search(r'\n\s*run\s*=\s*CommandListSkinTexture', section_match.group(1), flags=re.IGNORECASE):
                new_sections += section_match.group()
                continue

            needs_check = True
            new_sections += re.sub(
                r'\n\s*match_first_index\s*=.*?\n',
                r'\g<0>run = CommandListSkinTexture\n',
                section_match.group(),
                flags=re.IGNORECASE, count=1
            )


        if unindexed_section and not new_sections:
            if not re.search(r'\n\s*run\s*=\s*CommandListSkinTexture', unindexed_section, flags=re.IGNORECASE):
                needs_check = True
                unindexed_section = re.sub(
                    r'\n\s*hash\s*=.*?\n',
                    r'\g<0>run = CommandListSkinTexture\n',
                    unindexed_section,
                    flags=re.IGNORECASE, count=1
                )

        new_sections = unindexed_section + new_sections

        return ExecutionResult(
            touched        = False,
            failed         = False,
            signal_break   = False,
            queue_hashes   = None,
            queue_commands = (
                (log,                     ('+ Adding `run = CommandListSkinTexture`',)),
                (remove_indexed_sections, {'capture_position': '🌲'}),
                (create_new_section,      {'saved_position': '🌲', 'section_content': new_sections}),
            ) if needs_check else (
                (log,                     ('/ Skipping `run = CommandListSkinTexture` Addition',)),
            ),
        )


@dataclass
class add_section_if_missing():
    equiv_hashes    : tuple[str] | str
    section_title   : str = None
    section_content : str = field(default='')

    def execute(self, default_args: DefaultArgs):
        ini = default_args.ini

        if (type(self.equiv_hashes) is not tuple):
            self.equiv_hashes = (self.equiv_hashes,)
        for equiv_hash in self.equiv_hashes:
            if ini.has_hash(equiv_hash):
                return ExecutionResult(
                    touched        = False,
                    failed         = False,
                    signal_break   = False,
                    queue_hashes   = None,
                    queue_commands = (
                        (log, ('/ Skipping Section Addition', equiv_hash, f'[...{self.section_title}]',)),
                    ),
                )
        equiv_hash = self.equiv_hashes[0]

        section = '\n[TextureOverride{}]\n'.format(self.section_title)
        section += 'hash = {}\n'.format(equiv_hash)
        section += self.section_content

        return ExecutionResult(
            touched        = False,
            failed         = False,
            signal_break   = False,
            queue_hashes   = (equiv_hash,),
            queue_commands = (
                (log,                ('+ Adding Section', equiv_hash, f'[...{self.section_title}]',)),
                (capture_section,    {'capture_position': '🌲'}),
                (create_new_section, {'saved_position': '🌲', 'section_content': section}),
            ),
        )


@dataclass
class zzz_13_remap_texcoord():
    id: str
    old_format: tuple[str] # = ('4B','2e','2f','2e')
    new_format: tuple[str] # = ('4B','2f','2f','2f')

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini
        hash = default_args.hash
        tabs = default_args.tabs

        # Precompute new buffer strides and offsets
        # Check if existing buffer stride matches our expectations
        # before remapping it
        if (len(self.old_format) != len(self.new_format)): raise Exception()
        old_stride = struct.calcsize('<' + ''.join(self.old_format))
        new_stride = struct.calcsize('<' + ''.join(self.new_format))

        offset = 0
        offsets = [0]
        for format_chunk in self.old_format:
            offset += struct.calcsize(f'<{format_chunk}')
            offsets.append(offset)

        # Debugging
        # print(f'\t\tOld Format stride: {struct.calcsize('<' + ''.join(self.old_format))}')
        # print(f'\t\tNew Format stride: {struct.calcsize('<' + ''.join(self.new_format))}')
        # print(f'\t\tBuffer Stride: {stride}')
        # print(f'\t\tOffsets: {offsets}')

        # Need to find all Texcoord Resources used by this hash directly
        # through TextureOverrides or run through Commandlists... 
        pattern = get_section_hash_pattern(hash)
        section_match = pattern.search(ini.content)
        resources = process_commandlist(ini.content, section_match.group(1), 'vb1')

        # - Match Resource sections to find filenames of buffers 
        # - Update stride value of resources early instead of iterating again later
        buffer_filenames = set()
        line_pattern = re.compile(r'^\s*(filename|stride)\s*=\s*(.*)\s*$', flags=re.IGNORECASE)
        for resource in resources:
            pattern = get_section_title_pattern(resource)
            resource_section_match = pattern.search(ini.content)
            if not resource_section_match: continue

            modified_resource_section = []
            for line in resource_section_match.group(1).splitlines():
                line_match = line_pattern.match(line)
                if not line_match:
                    modified_resource_section.append(line)

                # Capture buffer filename
                elif line_match.group(1) == 'filename':
                    modified_resource_section.append(line)
                    buffer_filenames.add(line_match.group(2))

                # Update stride value of resource in ini
                elif line_match.group(1) == 'stride':
                    stride = int(line_match.group(2))
                    if stride != old_stride:
                        print('{}X WARNING [{}]! Expected buffer stride {} but got {} instead. Overriding and continuing.'.format('\t'*tabs, resource, old_stride, stride))
                    #     raise Exception('Remap failed for {}! Expected buffer stride {} but got {} instead.'.format(resource, old_stride, stride))

                    modified_resource_section.append('stride = {}'.format(new_stride))
                    modified_resource_section.append(';'+line)

            # Update ini
            modified_resource_section = '\n'.join(modified_resource_section)
            i, j = resource_section_match.span(1)
            ini.content = ini.content[:i] + modified_resource_section + ini.content[j:]

        global global_modified_buffers
        for buffer_filename in buffer_filenames:
            buffer_filepath = Path(Path(ini.filepath).parent/buffer_filename)
            buffer_dict_key = str(buffer_filepath.absolute())

            if buffer_dict_key not in global_modified_buffers:
                global_modified_buffers[buffer_dict_key] = []
            fix_id = f'{self.id}-texcoord_remap'
            if fix_id in global_modified_buffers[buffer_dict_key]: continue
            else: global_modified_buffers[buffer_dict_key].append(fix_id)

            if buffer_dict_key not in ini.modified_buffers:
                buffer = buffer_filepath.read_bytes()
            else:
                buffer = ini.modified_buffers[buffer_dict_key]

            vcount = len(buffer) // stride
            new_buffer = bytearray()
            for i in range(vcount):
                for j, (old_chunk, new_chunk) in enumerate(zip(self.old_format, self.new_format)):

                    if offsets[j] < stride and offsets[j+1] <= stride:

                        if old_chunk != new_chunk:
                            # HardCode VColor Remap
                            if (j == 0 and old_chunk == '4B' and new_chunk == '4f'):
                                new_buffer.extend(struct.pack('<4f', *[b/255 for b in struct.unpack_from('<4B', buffer, i*stride + 0)]))
                            elif (j == 0 and old_chunk == '4f' and new_chunk == '4B'):
                                new_buffer.extend(struct.pack('<4B', *[int(b*255) for b in struct.unpack_from('<4f', buffer, i*stride + 0)]))

                            # General Element Remap
                            else:
                                new_buffer.extend(struct.pack(f'<{new_chunk}', *struct.unpack_from(f'<{old_chunk}', buffer, i*stride+offsets[j])))

                        # No Element Remap Needed
                        else:
                            new_buffer.extend(buffer[i*stride + offsets[j]: i*stride + offsets[j+1]])

                    # Mod texcoord vertex data does not saturate the expected old stride
                    else: # cope
                        new_buffer.extend(struct.pack(f'<{new_chunk}', *([0] * int(new_chunk[0]))))
            
            ini.modified_buffers[buffer_dict_key] = new_buffer    

        return ExecutionResult(
            touched=True
        )


# Deprecated. Use generalized remap_texcoord instead
@dataclass
class zzz_12_shrink_texcoord_color():
    id: str

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini
        hash = default_args.hash
        tabs = default_args.tabs        

        # Need to find all Texcoord Resources used by this hash directly
        # through TextureOverrides or run through Commandlists... 
        pattern = get_section_hash_pattern(hash)
        section_match = pattern.search(ini.content)
        resources = process_commandlist(ini.content, section_match.group(1), 'vb1')

        # - Match Resource sections to find filenames of buffers 
        # - Update stride value of resources early instead of iterating again later
        buffer_filenames = set()
        line_pattern = re.compile(r'^\s*(filename|stride)\s*=\s*(.*)\s*$', flags=re.IGNORECASE)
        for resource in resources:
            pattern = get_section_title_pattern(resource)
            resource_section_match = pattern.search(ini.content)
            if not resource_section_match: continue

            modified_resource_section = []
            for line in resource_section_match.group(1).splitlines():
                line_match = line_pattern.match(line)
                if not line_match:
                    modified_resource_section.append(line)

                # Capture buffer filename
                elif line_match.group(1) == 'filename':
                    modified_resource_section.append(line)
                    buffer_filenames.add(line_match.group(2))

                # Update stride value of resource in ini
                elif line_match.group(1) == 'stride':
                    stride = int(line_match.group(2))
                    modified_resource_section.append('stride = {}'.format(stride - 12))
                    modified_resource_section.append(';'+line)

            # Update ini
            modified_resource_section = '\n'.join(modified_resource_section)
            i, j = resource_section_match.span(1)
            ini.content = ini.content[:i] + modified_resource_section + ini.content[j:]

        global global_modified_buffers
        for buffer_filename in buffer_filenames:
            buffer_filepath = Path(Path(ini.filepath).parent/buffer_filename)
            buffer_dict_key = str(buffer_filepath.absolute())

            if buffer_dict_key not in global_modified_buffers:
                global_modified_buffers[buffer_dict_key] = []
            fix_id = f'{self.id}-zzz_12_shrink_texcoord_color'
            if fix_id in global_modified_buffers[buffer_dict_key]: continue
            else: global_modified_buffers[buffer_dict_key].append(fix_id)

            if buffer_dict_key not in ini.modified_buffers:
                buffer = buffer_filepath.read_bytes()
            else:
                buffer = ini.modified_buffers[buffer_dict_key]

            vcount = len(buffer) // stride
            new_buffer = bytearray()
            for i in range(vcount):
                # print(*[ int((f*255)) for f in struct.unpack_from('<4f', buffer, i*stride + 0)])
                new_buffer.extend(struct.pack(
                        '<4B',
                        *[
                            int(f * 255)
                            for f in struct.unpack_from('<4f', buffer, i*stride + 0)
                        ]
                    ))
                new_buffer.extend(buffer[i*stride + 16: i*stride + stride])
            
            ini.modified_buffers[buffer_dict_key] = new_buffer            

        return ExecutionResult(
            touched=True
        )

@dataclass
class update_buffer_blend_indices():
    hash       : str
    old_indices: tuple[int]
    new_indices: tuple[int]

    def execute(self, default_args: DefaultArgs):
        ini  = default_args.ini

        # Need to find all Texcoord Resources used by this hash directly
        # through TextureOverrides or run through Commandlists... 
        pattern = get_section_hash_pattern(self.hash)
        section_match = pattern.search(ini.content)
        resources = process_commandlist(ini.content, section_match.group(1), 'vb2')

        # - Match Resource sections to find filenames of buffers 
        # - Update stride value of resources early instead of iterating again later
        buffer_filenames = set()
        line_pattern = re.compile(r'^\s*(filename|stride)\s*=\s*(.*)\s*$', flags=re.IGNORECASE)
        for resource in resources:
            pattern = get_section_title_pattern(resource)
            resource_section_match = pattern.search(ini.content)
            if not resource_section_match: continue

            modified_resource_section = []
            for line in resource_section_match.group(1).splitlines():
                line_match = line_pattern.match(line)
                if not line_match:
                    modified_resource_section.append(line)

                # Capture buffer filename
                elif line_match.group(1) == 'filename':
                    modified_resource_section.append(line)
                    buffer_filenames.add(line_match.group(2))

        for buffer_filename in buffer_filenames:
            buffer_filepath = Path(Path(ini.filepath).parent/buffer_filename)
            buffer_dict_key = str(buffer_filepath.absolute())

            if buffer_dict_key not in ini.modified_buffers:
                buffer = buffer_filepath.read_bytes()
            else:
                buffer = ini.modified_buffers[buffer_dict_key]
    
            new_buffer = bytearray()
            blend_stride = 32
            vertex_count = len(buffer)//blend_stride
            for i in range(vertex_count):
                blend_weights  = struct.unpack_from('<4f', buffer, i*blend_stride + 0)
                blend_indices  = struct.unpack_from('<4I', buffer, i*blend_stride + 16)

                new_buffer.extend(struct.pack('<4f4I', *blend_weights, *[
                    vgx if vgx not in self.old_indices
                    else self.new_indices[self.old_indices.index(vgx)]
                    for vgx in blend_indices
                ]))

            ini.modified_buffers[buffer_dict_key] = new_buffer

        return ExecutionResult(
            touched=True
        )



hash_commands = {
    # MARK: Anby
    '5c0240db': [(log, ('1.0: Anby Hair IB Hash',)), (add_ib_check_if_missing,)],
    '4816de84': [(log, ('1.0: Anby Body IB Hash',)), (add_ib_check_if_missing,)],
    '19df8e84': [(log, ('1.0: Anby Head IB Hash',)), (add_ib_check_if_missing,)],


    # reverted in 1.2
    # '496a781d': [
    #     (log, ('1.0: -> 1.1: Anby Hair Texcoord Hash',)),
    #     (update_hash, ('39538886',)),
    #     (log, ('+ Remapping texcoord buffer from stride 20 to 32',)),
    #     (update_buffer_element_width, (('BBBB', 'ee', 'ff', 'ee'), ('ffff', 'ee', 'ff', 'ee'), '1.1')),
    #     (log, ('+ Setting texcoord vcolor alpha to 1',)),
    #     (update_buffer_element_value, (('ffff', 'ee', 'ff', 'ee'), ('xxx1', 'xx', 'xx', 'xx'), '1.1'))
    # ],

    '39538886': [
        (log, ('1.1 -> 1.2: Anby Hair Texcoord Hash',)),
        (update_hash, ('496a781d',)),
        (log, ('+ Remapping texcoord buffer',)),
        (zzz_12_shrink_texcoord_color, ('1.2',))
    ],

    'cc114f4f': [(log, ('1.5 -> 1.6: Anby HeadA Diffuse 1024p Hash',)), (update_hash, ('692c6d2b',))],
    '692c6d2b': [
        (log,                           ('1.6: Anby HeadA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   (('05d7b504', '2a29cb9b'), 'Anby.HeadA.Diffuse.2048')),
    ],
    '2a29cb9b': [(log, ('1.5 -> 1.6: Anby HeadA Diffuse 2048p Hash',)), (update_hash, ('05d7b504',))],
    '05d7b504': [
        (log,                           ('1.6: Anby HeadA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   (('692c6d2b', 'cc114f4f'), 'Anby.HeadA.Diffuse.1024')),
    ],

    '6ea0023c': [
        (log,                           ('1.0: Anby HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('5c0240db', 'Anby.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7c7f96d2', 'Anby.HairA.Diffuse.1024')),
    ],
    '7c7f96d2': [
        (log,                           ('1.0: Anby HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('5c0240db', 'Anby.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6ea0023c', 'Anby.HairA.Diffuse.2048')),
    ],
    'b54f2a3d': [
        (log,                           ('1.0: Anby HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('5c0240db', 'Anby.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9ceea795', 'Anby.HairA.LightMap.1024')),
    ],
    '9ceea795': [
        (log,                           ('1.0: Anby HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('5c0240db', 'Anby.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b54f2a3d', 'Anby.HairA.LightMap.2048')),
    ],
    '20890a00': [
        (log,                           ('1.0: Anby HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('5c0240db', 'Anby.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3101f0da', 'Anby.HairA.NormalMap.1024')),
    ],
    '3101f0da': [
        (log,                           ('1.0: Anby HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('5c0240db', 'Anby.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('20890a00', 'Anby.HairA.NormalMap.2048')),
    ],

    'b37c3b4e': [(log, ('1.5 -> 1.6: Anby BodyA Diffuse 2048p Hash',)), (update_hash, ('215ff74d',))],
    '215ff74d': [
        (log,                           ('1.6: Anby BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('8df45cb8', '8bd7966f'), 'Anby.BodyA.Diffuse.1024')),
    ],
    '8bd7966f': [(log, ('1.5 -> 1.6: Anby BodyA Diffuse 1024p Hash',)), (update_hash, ('8df45cb8',))],
    '8df45cb8': [
        (log,                           ('1.6: Anby BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('215ff74d', 'b37c3b4e'), 'Anby.BodyA.Diffuse.2048')),
    ],
    '7c24acc9': [
        (log,                           ('1.0: Anby BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9cddbf1e', 'Anby.BodyA.LightMap.1024')),
    ],
    '9cddbf1e': [
        (log,                           ('1.0: Anby BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7c24acc9', 'Anby.BodyA.LightMap.2048')),
    ],
    'ccca3b8e': [
        (log,                           ('1.0: Anby BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1115f163', 'Anby.BodyA.MaterialMap.1024')),
    ],
    '1115f163': [
        (log,                           ('1.0: Anby BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ccca3b8e', 'Anby.BodyA.MaterialMap.2048')),
    ],
    '19226ead': [
        (log,                           ('1.0: Anby BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6346d69d', 'Anby.BodyA.NormalMap.1024')),
    ],
    '6346d69d': [
        (log,                           ('1.0: Anby BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('4816de84', 'Anby.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('19226ead', 'Anby.BodyA.NormalMap.2048')),
    ],



    # MARK: Anton
    '6b95c80d': [(log, ('1.0: Anton Hair IB Hash',)),   (add_ib_check_if_missing,)],
    '653fb27c': [(log, ('1.0: Anton Body IB Hash',)),   (add_ib_check_if_missing,)],
    'a21fcee4': [(log, ('1.0: Anton Jacket IB Hash',)), (add_ib_check_if_missing,)],
    'a0201907': [(log, ('1.0: Anton Head IB Hash',)),   (add_ib_check_if_missing,)],

    '15cb1aee': [
        (log,                           ('1.0: Anton HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('a0201907', 'Anton.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('842119d6', 'Anton.HeadA.Diffuse.2048')),
    ],
    '654134c1': [
        (log,                           ('1.0: Anton HeadA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('a0201907', 'Anton.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ac7fb2e2', 'Anton.HeadA.LightMap.2048')),
    ],
    '842119d6': [
        (log,                           ('1.0: Anton HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('a0201907', 'Anton.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('15cb1aee', 'Anton.HeadA.Diffuse.1024')),
    ],
    'ac7fb2e2': [
        (log,                           ('1.0: Anton HeadA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('a0201907', 'Anton.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('654134c1', 'Anton.HeadA.LightMap.1024')),
    ],

    '571aa398': [
        (log,                           ('1.0: Anton HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d4c4c604', 'Anton.HairA.Diffuse.1024')),
    ],
    'd4c4c604': [
        (log,                           ('1.0: Anton HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('571aa398', 'Anton.HairA.Diffuse.2048')),
    ],
    'ee06579e': [
        (log,                           ('1.0: Anton HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('21ee9a3f', 'Anton.HairA.LightMap.1024')),
    ],
    '21ee9a3f': [
        (log,                           ('1.0: Anton HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ee06579e', 'Anton.HairA.LightMap.2048')),
    ],
    '24caeb1f': [
        (log,                           ('1.0: Anton HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6fc654e1', 'Anton.HairA.MaterialMap.1024')),
    ],
    '6fc654e1': [
        (log,                           ('1.0: Anton HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('24caeb1f', 'Anton.HairA.MaterialMap.2048')),
    ],
    'b216f758': [
        (log,                           ('1.0: Anton HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('77ae203f', 'Anton.HairA.NormalMap.1024')),
    ],
    '77ae203f': [
        (log,                           ('1.0: Anton HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('6b95c80d', 'Anton.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b216f758', 'Anton.HairA.NormalMap.2048')),
    ],

    '00abcf22': [
        (log,                           ('1.0: Anton BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('581a0958', 'Anton.BodyA.Diffuse.1024')),
    ],
    '581a0958': [
        (log,                           ('1.0: Anton BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('00abcf22', 'Anton.BodyA.Diffuse.2048')),
    ],
    '17cf1b74': [
        (log,                           ('1.0: Anton BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8e5ba7d0', 'Anton.BodyA.LightMap.1024')),
    ],
    '8e5ba7d0': [
        (log,                           ('1.0: Anton BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('17cf1b74', 'Anton.BodyA.LightMap.2048')),
    ],
    '0238b0ff': [
        (log,                           ('1.0: Anton BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b7ce5f0b', 'Anton.BodyA.MaterialMap.1024')),
    ],
    'b7ce5f0b': [
        (log,                           ('1.0: Anton BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0238b0ff', 'Anton.BodyA.MaterialMap.2048')),
    ],
    '1b4ad5b7': [
        (log,                           ('1.0: Anton BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5b2ab0e0', 'Anton.BodyA.NormalMap.1024')),
    ],
    '5b2ab0e0': [
        (log,                           ('1.0: Anton BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('653fb27c', 'Anton.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1b4ad5b7', 'Anton.BodyA.NormalMap.2048')),
    ],

    'd4b15508': [
        (log,                           ('1.0: Anton JacketA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f7831517', 'Anton.JacketA.Diffuse.1024')),
    ],
    'f7831517': [
        (log,                           ('1.0: Anton JacketA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d4b15508', 'Anton.JacketA.Diffuse.2048')),
    ],
    '886a664a': [
        (log,                           ('1.0: Anton JacketA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c42628a5', 'Anton.JacketA.LightMap.1024')),
    ],
    'c42628a5': [
        (log,                           ('1.0: Anton JacketA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('886a664a', 'Anton.JacketA.LightMap.2048')),
    ],
    'd36a2f7a': [
        (log,                           ('1.0: Anton JacketA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('75bccc40', 'Anton.JacketA.MaterialMap.1024')),
    ],
    '75bccc40': [
        (log,                           ('1.0: Anton JacketA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d36a2f7a', 'Anton.JacketA.MaterialMap.2048')),
    ],
    'd7517d0e': [
        (log,                           ('1.0: Anton JacketA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ae3d5fb8', 'Anton.JacketA.NormalMap.1024')),
    ],
    'ae3d5fb8': [
        (log,                           ('1.0: Anton JacketA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('a21fcee4', 'Anton.Jacket.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d7517d0e', 'Anton.JacketA.NormalMap.2048')),
    ],


    # MARK: AstraYao
    '53cdac6c': [(log, ('1.5: AstraYao Hair IB Hash',)), (add_ib_check_if_missing,)],
    '7a110804': [(log, ('1.5: AstraYao Body IB Hash',)), (add_ib_check_if_missing,)],
    '92f33156': [(log, ('1.5: AstraYao Legs IB Hash',)), (add_ib_check_if_missing,)],
    '51831437': [(log, ('1.5: AstraYao Face IB Hash',)), (add_ib_check_if_missing,)],

    '77670042': [(log, ('1.5 -> 1.6: AstraYao Face Diffuse 1024p Hash',)), (update_hash, ('3283b8be',))],
    '3283b8be': [
        (log,                           ('1.6: AstraYao FaceA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('51831437', 'AstraYao.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('c41341b2', '3a8d0dfc'), 'AstraYao.FaceA.Diffuse.2048')),
    ],
    '3a8d0dfc': [(log, ('1.5 -> 1.6: AstraYao Face Diffuse 2048p Hash',)), (update_hash, ('c41341b2',))],
    'c41341b2': [
        (log,                           ('1.6: AstraYao FaceA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('51831437', 'AstraYao.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('3283b8be', '77670042'), 'AstraYao.FaceA.Diffuse.1024')),
    ],

    'da673df0': [(log, ('1.5A -> 1.5B: AstraYao HairA, LegsA Diffuse 2048p Hash',)), (update_hash, ('2daa2443',))],
    '2daa2443': [(log, ('1.5 -> 1.6: AstraYao HairA, LegsA Diffuse 2048p Hash',)),   (update_hash, ('e634238a',))],
    'e634238a': [
        (log,                           ('1.6: AstraYao HairA, LegsA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   (('56c71ea2', '4b1c1b47', '7a507e4a'), 'AstraYao.HairA.Diffuse.1024')),
    ],
    '34aad3b4': [(log, ('1.5A -> 1.5B: AstraYao HairA, LegsA LightMap 2048p Hash',)), (update_hash, ('b085765e',))],
    'b085765e': [(log, ('1.5 -> 1.6: AstraYao HairA, LegsA LightMap 2048p Hash',)),   (update_hash, ('34f0706c',))],
    '34f0706c': [
        (log,                           ('1.6: AstraYao HairA, LegsA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   (('fd3ca2a6', 'c47a524a', 'e4a4f975'), 'AstraYao.HairA.LightMap.1024')),
    ],
    'b53b2e12': [(log, ('1.5 -> 1.6: AstraYao HairA, LegsA MaterialMap 2048p Hash',)), (update_hash, ('883a578f',))],
    '883a578f': [
        (log,                           ('1.6: AstraYao HairA, LegsA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   (('759c15e0', '0be99d44'), 'AstraYao.HairA.MaterialMap.1024')),
    ],

    '7a507e4a': [(log, ('1.5A -> 1.5B: AstraYao HairA, LegsA Diffuse 1024p Hash',)), (update_hash, ('4b1c1b47',))],
    '4b1c1b47': [(log, ('1.5 -> 1.6: AstraYao HairA, LegsA Diffuse 1024p Hash',)),   (update_hash, ('56c71ea2',))],
    '56c71ea2': [
        (log,                           ('1.6: AstraYao HairA, LegsA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   (('e634238a', '2daa2443', 'da673df0'), 'AstraYao.HairA.Diffuse.2048')),
    ],
    'e4a4f975': [(log, ('1.5A -> 1.5B: AstraYao HairA, LegsA LightMap 1024p Hash',)), (update_hash, ('c47a524a',))],
    'c47a524a': [(log, ('1.5 -> 1.6: AstraYao HairA, LegsA LightMap 1024p Hash',)),   (update_hash, ('fd3ca2a6',))],
    'fd3ca2a6': [
        (log,                           ('1.6: AstraYao HairA, LegsA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   (('34f0706c', 'b085765e', '34aad3b4'), 'AstraYao.HairA.LightMap.2048')),
    ],
    '0be99d44': [(log, ('1.5 -> 1.6: AstraYao HairA, LegsA MaterialMap 1024p Hash',)), (update_hash, ('759c15e0',))],
    '759c15e0': [
        (log,                           ('1.6: AstraYao HairA, LegsA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   (('883a578f', 'b53b2e12'), 'AstraYao.HairA.MaterialMap.2048')),
    ],

    'd7f1c157': [
        (log,                           ('1.5: AstraYao BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('7a110804', 'AstraYao.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e523eb0f', 'AstraYao.BodyA.Diffuse.1024')),
    ],
    'dba7d767': [
        (log,                           ('1.5: AstraYao BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('7a110804', 'AstraYao.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3f9f0d8a', 'AstraYao.BodyA.LightMap.1024')),
    ],
    '21d5f5e3': [
        (log,                           ('1.5: AstraYao BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('7a110804', 'AstraYao.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c4248e2d', 'AstraYao.BodyA.MaterialMap.1024')),
    ],
    'e523eb0f': [
        (log,                           ('1.5: AstraYao BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('7a110804', 'AstraYao.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d7f1c157', 'AstraYao.BodyA.Diffuse.2048')),
    ],
    '3f9f0d8a': [
        (log,                           ('1.5: AstraYao BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('7a110804', 'AstraYao.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('dba7d767', 'AstraYao.BodyA.LightMap.2048')),
    ],
    'c4248e2d': [
        (log,                           ('1.5: AstraYao BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('7a110804', 'AstraYao.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('21d5f5e3', 'AstraYao.BodyA.MaterialMap.2048')),
    ],

    '3cd13d03': [(log, ('1.5 -> 1.6: AstraYao Body Blend Hash',)),    (update_hash, ('9d35c352',)),],
    'f8b92870': [(log, ('1.5 -> 1.6: AstraYao Hair Texcoord Hash',)), (update_hash, ('8ba0b335',)),],
    'da86a32e': [(log, ('1.5 -> 1.6: AstraYao Legs Texcoord Hash',)), (update_hash, ('1433ee78',)),],



    # MARK: Belle
    'bea4a483': [(log, ('1.0: Belle Hair IB Hash',)), (add_ib_check_if_missing,)],
    '1817f3ca': [(log, ('1.0: Belle Body IB Hash',)), (add_ib_check_if_missing,)],
    '9a9780a7': [(log, ('1.0: Belle Head IB Hash',)), (add_ib_check_if_missing,)],

    'caf95576': [
        (log,                         ('1.0 -> 1.1: Belle Body Texcoord Hash',)),
        (update_hash,                 ('801edbf4',)),
        (log,                         ('1.0 -> 1.1: Belle Body Blend Remap',)),
        (update_buffer_blend_indices, (
            'd2844c01',
            (3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 58, 59, 60, 61, 62, 63, 64, 65, 66, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 126, 127),
            (6, 7, 3, 5, 4, 18, 9, 10, 11, 12, 13, 14, 15, 16, 17, 21, 25, 24, 20, 22, 23, 38, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 47, 48, 53, 56, 45, 46, 49, 50, 51, 52, 54, 55, 60, 61, 66, 58, 59, 62, 63, 64, 65, 104, 95, 96, 97, 98, 99, 100, 101, 102, 103, 127, 126),
        ))
    ],

    '77eef7e8': [
        (log,                           ('1.0: Belle HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('9a9780a7', 'Belle.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('75ec3614', 'Belle.HeadA.Diffuse.2048')),
    ],
    '75ec3614': [
        (log,                           ('1.0: Belle HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('9a9780a7', 'Belle.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('77eef7e8', 'Belle.HeadA.Diffuse.1024')),
    ],

    '1ce58567': [
        (log,                           ('1.0: Belle HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('08f04d95', 'Belle.HairA.Diffuse.1024')),
    ],
    '08f04d95': [
        (log,                           ('1.0: Belle HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1ce58567', 'Belle.HairA.Diffuse.2048')),
    ],
    'f1ee2105': [
        (log,                           ('1.0: Belle HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('2e656f2f', 'Belle.HairA.LightMap.1024')),
    ],
    '2e656f2f': [
        (log,                           ('1.0: Belle HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f1ee2105', 'Belle.HairA.LightMap.2048')),
    ],
    '24c47ca5': [(log, ('1.4 -> 1.5: Belle HairA MaterialMap 2048p Hash',)), (update_hash, ('34bdb036',))],
    '34bdb036': [
        (log,                           ('1.0: Belle HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('7542ef4b', '4b6ef993'), 'Belle.HairA.MaterialMap.1024')),
    ],
    '4b6ef993': [(log, ('1.4 -> 1.5: Belle HairA MaterialMap 1024p Hash',)), (update_hash, ('7542ef4b',))],
    '7542ef4b': [
        (log,                           ('1.0: Belle HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('34bdb036', '24c47ca5'), 'Belle.HairA.MaterialMap.2048')),
    ],
    '89b147ff': [
        (log,                           ('1.0: Belle HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6b55c039', 'Belle.HairA.NormalMap.1024')),
    ],
    '6b55c039': [
        (log,                           ('1.0: Belle HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('bea4a483', 'Belle.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('89b147ff', 'Belle.HairA.NormalMap.2048')),
    ],
    
    'd2960560': [(log, ('1.4 -> 1.5: Belle BodyA Diffuse 2048p Hash',)), (update_hash, ('24639b77',))],
    '24639b77': [
        (log,                           ('1.0: Belle BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('b9c7f71b', '4454fb58'), 'Belle.BodyA.Diffuse.1024')),
    ],
    '4454fb58': [(log, ('1.4 -> 1.5: Belle BodyA Diffuse 1024p Hash',)), (update_hash, ('b9c7f71b',))],
    'b9c7f71b': [
        (log,                           ('1.0: Belle BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('24639b77', 'd2960560'), 'Belle.BodyA.Diffuse.2048')),
    ],
    'bf286c84': [(log, ('1.4 -> 1.5: Belle BodyA LightMap 2048p Hash',)), (update_hash, ('7947679c',))],
    '7947679c': [
        (log,                           ('1.0: Belle BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('a4d3687d', '2ed82c57'), 'Belle.BodyA.LightMap.1024')),
    ],
    '2ed82c57': [(log, ('1.4 -> 1.5: Belle BodyA LightMap 1024p Hash',)), (update_hash, ('a4d3687d',))],
    'a4d3687d': [
        (log,                           ('1.0: Belle BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('7947679c', 'bf286c84'), 'Belle.BodyA.LightMap.2048')),
    ],
    '33f28c6d': [
        (log,                           ('1.0: Belle BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b1abe877', 'Belle.BodyA.MaterialMap.1024')),
    ],
    'b1abe877': [
        (log,                           ('1.0: Belle BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('33f28c6d', 'Belle.BodyA.MaterialMap.2048')),
    ],
    'f04f7ab9': [
        (log,                           ('1.0: Belle BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c0bd8516', 'Belle.BodyA.NormalMap.1024')),
    ],
    'c0bd8516': [
        (log,                           ('1.0: Belle BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('1817f3ca', 'Belle.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f04f7ab9', 'Belle.BodyA.NormalMap.2048')),
    ],



    # MARK: Ben
    '9c4f1a9a': [(log, ('1.0: Ben Hair IB Hash',)), (add_ib_check_if_missing,)],
    '94288cca': [(log, ('1.0: Ben Body IB Hash',)), (add_ib_check_if_missing,)],

    '00002f2c': [
        (log,                           ('1.0: Ben HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8d83daba', 'Ben.HairA.Diffuse.1024')),
    ],
    '8d83daba': [
        (log,                           ('1.0: Ben HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('00002f2c', 'Ben.HairA.Diffuse.2048')),
    ],
    'cc195dc5': [
        (log,                           ('1.0: Ben HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1439d2b9', 'Ben.HairA.LightMap.1024')),
    ],
    '1439d2b9': [
        (log,                           ('1.0: Ben HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('cc195dc5', 'Ben.HairA.LightMap.2048')),
    ],
    '0bbceea0': [
        (log,                           ('1.0: Ben HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d665246d', 'Ben.HairA.MaterialMap.1024')),
    ],
    'd665246d': [
        (log,                           ('1.0: Ben HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0bbceea0', 'Ben.HairA.MaterialMap.2048')),
    ],
    '894ea737': [
        (log,                           ('1.0: Ben HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ba809960', 'Ben.HairA.NormalMap.1024')),
    ],
    'ba809960': [
        (log,                           ('1.0: Ben HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('9c4f1a9a', 'Ben.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('894ea737', 'Ben.HairA.NormalMap.2048')),
    ],

    '0313ed95': [
        (log,                           ('1.0: Ben BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d8dc4645', 'Ben.BodyA.Diffuse.1024')),
    ],
    'd8dc4645': [
        (log,                           ('1.0: Ben BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0313ed95', 'Ben.BodyA.Diffuse.2048')),
    ],
    'cb84ed5e': [
        (log,                           ('1.0: Ben BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6a80c2d8', 'Ben.BodyA.LightMap.1024')),
    ],
    '6a80c2d8': [
        (log,                           ('1.0: Ben BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('cb84ed5e', 'Ben.BodyA.LightMap.2048')),
    ],
    '3f4f6bc0': [
        (log,                           ('1.0: Ben BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('decc28c5', 'Ben.BodyA.MaterialMap.1024')),
    ],
    'decc28c5': [
        (log,                           ('1.0: Ben BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3f4f6bc0', 'Ben.BodyA.MaterialMap.2048')),
    ],
    '1b79fa5c': [
        (log,                           ('1.0: Ben BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f6ecc618', 'Ben.BodyA.NormalMap.1024')),
    ],
    'f6ecc618': [
        (log,                           ('1.0: Ben BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('94288cca', 'Ben.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1b79fa5c', 'Ben.BodyA.NormalMap.2048')),
    ],



    # MARK: Billy
    '21e98aeb': [(log, ('1.0: Billy Hair IB Hash',)), (add_ib_check_if_missing,)],
    '3371580a': [(log, ('1.0: Billy Body IB Hash',)), (add_ib_check_if_missing,)],
    'dc7978f3': [(log, ('1.0: Billy Head IB Hash',)), (add_ib_check_if_missing,)],


    'a1d68c9e': [
        (log,                           ('1.0: Billy HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6f8a9cdb', 'Billy.HeadA.Diffuse.2048')),
    ],
    'eed0cd5f': [
        (log,                           ('1.0: Billy HeadA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e5f2fc35', 'Billy.HeadA.NormalMap.2048')),
    ],
    '877e1a0d': [
        (log,                           ('1.0: Billy HeadA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9f02ef2b', 'Billy.HeadA.LightMap.2048')),
    ],
    'dc2f2dd2': [
        (log,                           ('1.0: Billy HeadA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d166c3e5', 'Billy.HeadA.MaterialMap.2048')),
    ],
    '6f8a9cdb': [
        (log,                           ('1.0: Billy HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a1d68c9e', 'Billy.HeadA.Diffuse.1024')),
    ],
    'e5f2fc35': [
        (log,                           ('1.0: Billy HeadA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('eed0cd5f', 'Billy.HeadA.NormalMap.1024')),
    ],
    '9f02ef2b': [
        (log,                           ('1.0: Billy HeadA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('877e1a0d', 'Billy.HeadA.LightMap.1024')),
    ],
    'd166c3e5': [
        (log,                           ('1.0: Billy HeadA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('dc7978f3', 'Billy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('dc2f2dd2', 'Billy.HeadA.MaterialMap.1024')),
    ],

    '0475db07': [
        (log,                           ('1.0: Billy HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('21e98aeb', 'Billy.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c0360c81', 'Billy.HairA.Diffuse.1024')),
    ],
    'c0360c81': [
        (log,                           ('1.0: Billy HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('21e98aeb', 'Billy.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0475db07', 'Billy.HairA.Diffuse.2048')),
    ],
    '4817b1bc': [
        (log,                           ('1.0: Billy HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('21e98aeb', 'Billy.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d269a0a1', 'Billy.HairA.LightMap.1024')),
    ],
    'd269a0a1': [
        (log,                           ('1.0: Billy HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('21e98aeb', 'Billy.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4817b1bc', 'Billy.HairA.LightMap.2048')),
    ],
    '47bbe297': [
        (log,                           ('1.0: Billy HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('21e98aeb', 'Billy.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('27185819', 'Billy.HairA.NormalMap.1024')),
    ],
    '27185819': [
        (log,                           ('1.0: Billy HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('21e98aeb', 'Billy.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('47bbe297', 'Billy.HairA.NormalMap.2048')),
    ],

    '399d9865': [
        (log,                           ('1.0: Billy BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('af07a583', 'Billy.BodyA.Diffuse.1024')),
    ],
    'af07a583': [
        (log,                           ('1.0: Billy BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('399d9865', 'Billy.BodyA.Diffuse.2048')),
    ],
    '789b054e': [
        (log,                           ('1.0: Billy BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0d5d374f', 'Billy.BodyA.LightMap.1024')),
    ],
    '0d5d374f': [
        (log,                           ('1.0: Billy BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('789b054e', 'Billy.BodyA.LightMap.2048')),
    ],
    '9cb20fa9': [
        (log,                           ('1.0: Billy BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b3cabf65', 'Billy.BodyA.MaterialMap.1024')),
    ],
    'b3cabf65': [
        (log,                           ('1.0: Billy BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9cb20fa9', 'Billy.BodyA.MaterialMap.2048')),
    ],
    '56b5953e': [
        (log,                           ('1.0: Billy BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('71d95d5d', 'Billy.BodyA.NormalMap.1024')),
    ],
    '71d95d5d': [
        (log,                           ('1.0: Billy BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('3371580a', 'Billy.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('56b5953e', 'Billy.BodyA.NormalMap.2048')),
    ],


    # MARK: Burnice
    'f779fb81': [(log, ('1.2: Burnice Hair IB Hash',)), (add_ib_check_if_missing,)],
    'af63e974': [(log, ('1.2: Burnice Body IB Hash',)), (add_ib_check_if_missing,)],
    'b3f6fcb3': [(log, ('1.2: Burnice Head IB Hash',)), (add_ib_check_if_missing,)],

    'c9c87bb1': [(log, ('1.3 -> 1.4: Burnice HeadA Diffuse 1024p Hash',)), (update_hash, ('68f0fb19',)),],
    '68f0fb19': [
        (log,                           ('1.4: Burnice HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('b3f6fcb3', 'Burnice.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('c4b6bb10', 'e338bb82'), 'Burnice.HeadA.Diffuse.2048')),
    ],
    'e338bb82': [(log, ('1.3 -> 1.4: Burnice HeadA Diffuse 2048p Hash',)), (update_hash, ('c4b6bb10',)),],
    'c4b6bb10': [
        (log,                           ('1.4: Burnice HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('b3f6fcb3', 'Burnice.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('68f0fb19', 'c9c87bb1'), 'Burnice.HeadA.Diffuse.1024')),
    ],

    '609b50a9': [
        (log,                           ('1.2: Burnice HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4568c6b3', 'Burnice.HairA.Diffuse.1024')),
    ],
    '4568c6b3': [
        (log,                           ('1.2: Burnice HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('609b50a9', 'Burnice.HairA.Diffuse.2048')),
    ],
    'bf0042b9': [
        (log,                           ('1.2: Burnice HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('08770e8c', 'Burnice.HairA.LightMap.1024')),
    ],
    '08770e8c': [
        (log,                           ('1.2: Burnice HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bf0042b9', 'Burnice.HairA.LightMap.2048')),
    ],
    '5f2840f1': [
        (log,                           ('1.2: Burnice HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3ae3ea20', 'Burnice.HairA.MaterialMap.1024')),
    ],
    '3ae3ea20': [
        (log,                           ('1.2: Burnice HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5f2840f1', 'Burnice.HairA.MaterialMap.2048')),
    ],
    '438cf629': [
        (log,                           ('1.2: Burnice HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0050e0d2', 'Burnice.HairA.NormalMap.1024')),
    ],
    '0050e0d2': [
        (log,                           ('1.2: Burnice HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('f779fb81', 'Burnice.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('438cf629', 'Burnice.HairA.NormalMap.2048')),
    ],

    '50bf6521': [
        (log,                           ('1.2: Burnice BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f0e67001', 'Burnice.BodyA.Diffuse.1024')),
    ],
    'f0e67001': [
        (log,                           ('1.2: Burnice BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('50bf6521', 'Burnice.BodyA.Diffuse.2048')),
    ],
    'f4e05ee7': [
        (log,                           ('1.2: Burnice BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0a3ba8ac', 'Burnice.BodyA.LightMap.1024')),
    ],
    '0a3ba8ac': [
        (log,                           ('1.2: Burnice BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f4e05ee7', 'Burnice.BodyA.LightMap.2048')),
    ],
    'c321481d': [
        (log,                           ('1.2: Burnice BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e37e7622', 'Burnice.BodyA.MaterialMap.1024')),
    ],
    'e37e7622': [
        (log,                           ('1.2: Burnice BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c321481d', 'Burnice.BodyA.MaterialMap.2048')),
    ],
    '0f2c69e2': [
        (log,                           ('1.2: Burnice BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0c4f338a', 'Burnice.BodyA.NormalMap.1024')),
    ],
    '0c4f338a': [
        (log,                           ('1.2: Burnice BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('af63e974', 'Burnice.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0f2c69e2', 'Burnice.BodyA.NormalMap.2048')),
    ],



    # MARK: Caesar
    '7a8fa826': [(log, ('1.2: Caesar Hair IB Hash',)), (add_ib_check_if_missing,)],
    '92061e5e': [(log, ('1.2: Caesar Body IB Hash',)), (add_ib_check_if_missing,)],
    '6caaeb53': [(log, ('1.2: Caesar Head IB Hash',)), (add_ib_check_if_missing,)],

    'af291513': [
        (log,            ('1.2 -> 1.3: Caesar Hair Texcoord Hash',)),
        (update_hash,    ('72537fa3',)),
        (log,            ('+ Remapping texcoord buffer',)),
        (zzz_13_remap_texcoord, (
            '13_Caesar_hair',
            ('4B','2e','2f','2e'),
            ('4B','2f','2f','2f')
        )),
    ],
    '3b2a70a5': [
        (log,            ('1.2 -> 1.3: Caesar Body Texcoord Hash',)),
        (update_hash,    ('0ca81129',)),
        (log,            ('+ Remapping texcoord buffer',)),
        (zzz_13_remap_texcoord, (
            '13_Caesar_body',
            ('4B','2e','2f','2e', '2e'),
            ('4B','2f','2f','2f', '2f')
        )),
    ],

    '84d53514': [
        (log,                           ('1.2: Caesar HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('6caaeb53', 'Caesar.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('13098244', 'Caesar.HeadA.Diffuse.2048')),
    ],
    '13098244': [
        (log,                           ('1.2: Caesar HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('6caaeb53', 'Caesar.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('84d53514', 'Caesar.HeadA.Diffuse.1024')),
    ],

    '9ce3e80c': [
        (log,                           ('1.2: Caesar HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b004ab49', 'Caesar.HairA.Diffuse.1024')),
    ],
    'b004ab49': [
        (log,                           ('1.2: Caesar HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9ce3e80c', 'Caesar.HairA.Diffuse.2048')),
    ],
    'bf19954f': [
        (log,                           ('1.2: Caesar HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c7115c4b', 'Caesar.HairA.LightMap.1024')),
    ],
    'c7115c4b': [
        (log,                           ('1.2: Caesar HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bf19954f', 'Caesar.HairA.LightMap.2048')),
    ],
    '350b827e': [
        (log,                           ('1.2: Caesar HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('2204f89a', 'Caesar.HairA.MaterialMap.1024')),
    ],
    '2204f89a': [
        (log,                           ('1.2: Caesar HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('350b827e', 'Caesar.HairA.MaterialMap.2048')),
    ],
    '10af3807': [
        (log,                           ('1.2: Caesar HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e17b3529', 'Caesar.HairA.NormalMap.1024')),
    ],
    'e17b3529': [
        (log,                           ('1.2: Caesar HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('7a8fa826', 'Caesar.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('10af3807', 'Caesar.HairA.NormalMap.2048')),
    ],

    '5e2cea1a': [
        (log,                           ('1.2: Caesar BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f4b78da0', 'Caesar.BodyA.Diffuse.1024')),
    ],
    'f4b78da0': [
        (log,                           ('1.2: Caesar BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5e2cea1a', 'Caesar.BodyA.Diffuse.2048')),
    ],
    '6296d481': [
        (log,                           ('1.2: Caesar BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a9e24ba0', 'Caesar.BodyA.LightMap.1024')),
    ],
    'a9e24ba0': [
        (log,                           ('1.2: Caesar BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6296d481', 'Caesar.BodyA.LightMap.2048')),
    ],
    'd5d89d5b': [
        (log,                           ('1.2: Caesar BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('328bc108', 'Caesar.BodyA.MaterialMap.1024')),
    ],
    '328bc108': [
        (log,                           ('1.2: Caesar BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d5d89d5b', 'Caesar.BodyA.MaterialMap.2048')),
    ],

    'c1f1e12f': [(log, ('1.3 -> 1.4: Caesar BodyA NormalMap 2048p Hash',)),   (update_hash, ('36f39b49',)),],
    'f1c6c309': [(log, ('1.4B -> 1.4C: Caesar BodyA NormalMap 2048p Hash',)), (update_hash, ('36f39b49',)),],
    '36f39b49': [
        (log,                           ('1.4: Caesar BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('a8abff9d', '8cdf95d0'), 'Caesar.BodyA.NormalMap.1024')),
    ],
    '8cdf95d0': [(log, ('1.3 -> 1.4: Caesar BodyA NormalMap 1024p Hash',)), (update_hash, ('a8abff9d',)),],
    'a8abff9d': [
        (log,                           ('1.4: Caesar BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('92061e5e', 'Caesar.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('36f39b49', 'f1c6c309', 'c1f1e12f'), 'Caesar.BodyA.NormalMap.2048')),
    ],



    # MARK: Corin
    '5a839fb2': [(log, ('1.0: Corin Hair IB Hash',)), (add_ib_check_if_missing,)],
    'e74620b5': [(log, ('1.0: Corin Body IB Hash',)), (add_ib_check_if_missing,)],
    '5f803336': [(log, ('1.0: Corin Bear IB Hash',)), (add_ib_check_if_missing,)],
    'a0c80593': [(log, ('1.0: Corin Head IB Hash',)), (add_ib_check_if_missing,)],


    '8d999156': [(log, ('1.3 -> 1.4: Corin Hair Blend Hash',)),    (update_hash, ('5fa50113',)),],
    '2cf242f4': [(log, ('1.3 -> 1.4: Corin Hair Texcoord Hash',)), (update_hash, ('abc95b03',)),],

    '97022d3c': [
        (log,                           ('1.0: Corin HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('a0c80593', 'Corin.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6d662824', 'Corin.HeadA.Diffuse.2048')),
    ],
    '6d662824': [
        (log,                           ('1.0: Corin HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('a0c80593', 'Corin.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('97022d3c', 'Corin.HeadA.Diffuse.1024')),
    ],

    '60526444': [
        (log,                           ('1.0: Corin HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('651e96f8', 'Corin.HairA.Diffuse.1024')),
    ],
    '651e96f8': [
        (log,                           ('1.0: Corin HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('60526444', 'Corin.HairA.Diffuse.2048')),
    ],
    '929aca42': [
        (log,                           ('1.0: Corin HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('edff2372', 'Corin.HairA.LightMap.1024')),
    ],
    'edff2372': [
        (log,                           ('1.0: Corin HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('929aca42', 'Corin.HairA.LightMap.2048')),
    ],
    # '23b4c60d': [
    #     (log,                           ('1.0: Corin HairA MaterialMap 2048p Hash',)),
    #     (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
    #     (multiply_section_if_missing,   ('1b88e01e', 'Corin.HairA.MaterialMap.1024')),
    # ],
    # '1b88e01e': [
    #     (log,                           ('1.0: Corin HairA MaterialMap 1024p Hash',)),
    #     (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
    #     (multiply_section_if_missing,   ('23b4c60d', 'Corin.HairA.MaterialMap.2048')),
    # ],
    '4a68ef99': [
        (log,                           ('1.0: Corin HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ab8956c8', 'Corin.HairA.NormalMap.1024')),
    ],
    'ab8956c8': [
        (log,                           ('1.0: Corin HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('5a839fb2', 'Corin.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4a68ef99', 'Corin.HairA.NormalMap.2048')),
    ],


    'af9d845a': [
        (log,                           ('1.0: Corin BodyA, BearA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('681f5162', 'Corin.BodyA.Diffuse.1024')),
    ],
    '681f5162': [
        (log,                           ('1.0: Corin BodyA, BearA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('af9d845a', 'Corin.BodyA.Diffuse.2048')),
    ],
    '75e05cdc': [
        (log,                           ('1.0: Corin BodyA, BearA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('af7eda82', 'Corin.BodyA.LightMap.1024')),
    ],
    'af7eda82': [
        (log,                           ('1.0: Corin BodyA, BearA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('75e05cdc', 'Corin.BodyA.LightMap.2048')),
    ],
    '50a0faea': [
        (log,                           ('1.0: Corin BodyA, BearA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('9dc9c0f6', 'Corin.BodyA.MaterialMap.1024')),
    ],
    '9dc9c0f6': [
        (log,                           ('1.0: Corin BodyA, BearA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('50a0faea', 'Corin.BodyA.MaterialMap.2048')),
    ],
    '289f4c58': [
        (log,                           ('1.0: Corin BodyA, BearA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('640141d4', 'Corin.BodyA.NormalMap.1024')),
    ],
    '640141d4': [
        (log,                           ('1.0: Corin BodyA, BearA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('289f4c58', 'Corin.BodyA.NormalMap.2048')),
    ],



    # MARK: Ellen
    'd44a8015': [(log, ('1.1: Ellen Hair IB Hash',)), (add_ib_check_if_missing,)],
    'e30fae03': [(log, ('1.1: Ellen Body IB Hash',)), (add_ib_check_if_missing,)],
    'f6ef8f3a': [(log, ('1.1: Ellen Head IB Hash',)), (add_ib_check_if_missing,)],

    '9c7fac5a': [(log, ('1.0 -> 1.1: Ellen Head IB Hash',)),       (update_hash, ('f6ef8f3a',))],
    '7f89a2b3': [(log, ('1.0 -> 1.1: Ellen Hair IB Hash',)),       (update_hash, ('d44a8015',))],
    'a72cfb34': [(log, ('1.0 -> 1.1: Ellen Body IB Hash',)),       (update_hash, ('e30fae03',))],


    '83dfd744': [(log, ('1.0 -> 1.1: Ellen Head Texcoord Hash',)), (update_hash, ('8744badf',))],


    'd59a5fec': [(log, ('1.0 -> 1.1: Ellen Hair Draw Hash',)),     (update_hash, ('77ac5f85',))],
    'a5448398': [(log, ('1.0 -> 1.1: Ellen Hair Position Hash',)), (update_hash, ('ba0fe600',))],
    '9cddb082': [
        (log, ('1.0 -> 1.1: Ellen Hair Texcoord Hash',)),
        (update_hash, ('5c33833e',)),
        (log, ('+ Remapping texcoord buffer from stride 24 to 36',)),
        (zzz_13_remap_texcoord, ('11_Ellen_Hair', ('4B', '2e', '2f', '2e', '2e'), ('4f', '2e', '2f', '2e', '2e'))), # attention
    ],

    '5c33833e': [
        (log, ('1.1 -> 1.2: Ellen Hair Texcoord Hash',)),
        (update_hash, ('a27a8e1a',)),
        (log, ('+ Remapping texcoord buffer from stride 36 to 24',)),
        (zzz_12_shrink_texcoord_color, ('1.2',))
    ],
    '52188576': [
        (log,                         ('1.3 -> 1.4: Ellen Hair Blend Remap',)),
        (update_buffer_blend_indices, (
            '52188576',
            (34, 35, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 49, 50),
            (39, 34, 40, 35, 38, 42, 43, 44, 45, 46, 47, 41, 50, 49),
        )),
        (update_hash,                 ('e91c93e0',)),
    ],


    '7bd3f8c2': [(log, ('1.0 -> 1.1: Ellen Body Draw Hash',)),     (update_hash, ('cdce1fc2',))],
    '89d5fba4': [(log, ('1.0 -> 1.1: Ellen Body Position Hash',)), (update_hash, ('b78f3616',))],
    '26966844': [(log, ('1.0 -> 1.1: Ellen Body Texcoord Hash',)), (update_hash, ('5ac6d5ee',))],
    '89589539': [(log, ('1.5 -> 1.6: Ellen Body Blend Hash',)),    (update_hash, ('ed9cb852',))],


    '09d55bce': [(log, ('1.0 -> 1.1: Ellen HeadA Diffuse 2048p Hash',)), (update_hash, ('465a66eb',))],
    '465a66eb': [
        (log,                           ('1.1: Ellen HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('f6ef8f3a', '9c7fac5a'), 'Ellen.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('4808d050', 'e6b27e31'), 'Ellen.HeadA.Diffuse.1024')),
    ],
    'e6b27e31': [(log, ('1.0 -> 1.1: Ellen HeadA Diffuse 1024p Hash',)), (update_hash, ('4808d050',))],
    '4808d050': [
        (log,                           ('1.1: Ellen HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('f6ef8f3a', '9c7fac5a'), 'Ellen.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('465a66eb', '09d55bce'), 'Ellen.HeadA.Diffuse.2048')),
    ],


    '81ccd2e2': [
        (log,                           ('1.0: Ellen HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1440e534', 'Ellen.HairA.Diffuse.1024')),
    ],
    '1440e534': [
        (log,                           ('1.0: Ellen HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('81ccd2e2', 'Ellen.HairA.Diffuse.2048')),
    ],
    'dc9d8b6e': [
        (log,                           ('1.0: Ellen HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8c835faa', 'Ellen.HairA.LightMap.1024')),
    ],
    '8c835faa': [
        (log,                           ('1.0: Ellen HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('dc9d8b6e', 'Ellen.HairA.LightMap.2048')),
    ],
    '01bb8189': [
        (log,                           ('1.0: Ellen HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b21b8370', 'Ellen.HairA.MaterialMap.1024')),
    ],
    'b21b8370': [
        (log,                           ('1.0: Ellen HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('01bb8189', 'Ellen.HairA.MaterialMap.2048')),
    ],
    'aaadca31': [
        (log,                           ('1.0: Ellen HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d6715e09', 'Ellen.HairA.NormalMap.1024')),
    ],
    'd6715e09': [
        (log,                           ('1.0: Ellen HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('d44a8015', '7f89a2b3'), 'Ellen.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('aaadca31', 'Ellen.HairA.NormalMap.2048')),
    ],


    'cf5f5fed': [
        (log,                           ('1.0: -> 1.1: Ellen BodyA Diffuse 2048p Hash',)),
        (update_hash,                   ('163e2559',)),
    ],
    '163e2559': [
        (log,                           ('1.1: Ellen BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('22fa0cd6', '94c15986'), 'Ellen.BodyA.Diffuse.1024')),
    ],
    '94c15986': [
        (log,                           ('1.0: -> 1.1: Ellen BodyA Diffuse 1024p Hash',)),
        (update_hash,                   ('22fa0cd6',)),
    ],
    '22fa0cd6': [
        (log,                           ('1.1: Ellen BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('163e2559', 'cf5f5fed'), 'Ellen.BodyA.Diffuse.2048')),
    ],
    'ff26fb83': [
        (log,                           ('1.0: Ellen BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('cea7516a', 'Ellen.BodyA.LightMap.1024')),
    ],
    'cea7516a': [
        (log,                           ('1.0: Ellen BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ff26fb83', 'Ellen.BodyA.LightMap.2048')),
    ],
    'f4487235': [
        (log,                           ('1.0: Ellen BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('30dc14d7', 'Ellen.BodyA.MaterialMap.1024')),
    ],
    '30dc14d7': [
        (log,                           ('1.0: Ellen BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f4487235', 'Ellen.BodyA.MaterialMap.2048')),
    ],
    '798c3a51': [
        (log,                           ('1.0: Ellen BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('590880e5', 'Ellen.BodyA.NormalMap.1024')),
    ],
    '590880e5': [
        (log,                           ('1.0: Ellen BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('e30fae03', 'a72cfb34'), 'Ellen.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('798c3a51', 'Ellen.BodyA.NormalMap.2048')),
    ],



    # MARK: Evelyn
    '10a5bde2': [(log, ('1.5: Evelyn Hair IB Hash',)),      (add_ib_check_if_missing,)],
    '04b53ecd': [(log, ('1.5: Evelyn Body IB Hash',)),      (add_ib_check_if_missing,)],
    'bb6d1023': [(log, ('1.5: Evelyn Jacket IB Hash',)),    (add_ib_check_if_missing,)],
    'b3eaedb0': [(log, ('1.5: Evelyn Shoulders IB Hash',)), (add_ib_check_if_missing,)],
    'ddf4efa6': [(log, ('1.5: Evelyn Face IB Hash',)),      (add_ib_check_if_missing,)],

    '8e1d1a6f': [
        (log,                           ('1.5: Evelyn FaceA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('ddf4efa6', 'Evelyn.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bc090438', 'Evelyn.FaceA.Diffuse.1024')),
    ],
    'bc090438': [
        (log,                           ('1.5: Evelyn FaceA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('ddf4efa6', 'Evelyn.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8e1d1a6f', 'Evelyn.FaceA.Diffuse.2048')),
    ],


    '0e5c3c97': [
        (log,                           ('1.5: Evelyn Hair, Jacket Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('65a7592d', 'Evelyn.Hair.Diffuse.1024')),
    ],
    'e1434e0d': [
        (log,                           ('1.5: Evelyn Hair, Jacket LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('eb414a98', 'Evelyn.Hair.LightMap.1024')),
    ],
    'b2718585': [
        (log,                           ('1.5: Evelyn Hair, Jacket MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('e680f0c7', 'Evelyn.Hair.MaterialMap.1024')),
    ],
    '65a7592d': [
        (log,                           ('1.5: Evelyn Hair, Jacket Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('0e5c3c97', 'Evelyn.Hair.Diffuse.2048')),
    ],
    'eb414a98': [
        (log,                           ('1.5: Evelyn Hair, Jacket LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('e1434e0d', 'Evelyn.Hair.LightMap.2048')),
    ],
    'e680f0c7': [
        (log,                           ('1.5: Evelyn Hair, Jacket MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('b2718585', 'Evelyn.Hair.MaterialMap.2048')),
    ],

    'a59b14c0': [
        (log,                           ('1.5: Evelyn Body, Shoulder Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('93033898', 'Evelyn.Body.Diffuse.1024')),
    ],
    'd022d32c': [
        (log,                           ('1.5: Evelyn Body, Shoulder LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('16aab2ab', 'Evelyn.Body.LightMap.1024')),
    ],
    '8624e4e4': [
        (log,                           ('1.5: Evelyn Body, Shoulder MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('716561f0', 'Evelyn.Body.MaterialMap.1024')),
    ],
    '93033898': [
        (log,                           ('1.5: Evelyn Body, Shoulder Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('a59b14c0', 'Evelyn.Body.Diffuse.2048')),
    ],
    '16aab2ab': [
        (log,                           ('1.5: Evelyn Body, Shoulder LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('d022d32c', 'Evelyn.Body.LightMap.2048')),
    ],
    '716561f0': [
        (log,                           ('1.5: Evelyn Body, Shoulder MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('8624e4e4', 'Evelyn.Body.MaterialMap.2048')),
    ],



    # MARK: Grace
    '89299f56': [(log, ('1.0: Grace Hair IB Hash',)), (add_ib_check_if_missing,)],
    '8b240678': [(log, ('1.2: Grace Body IB Hash',)), (add_ib_check_if_missing,)],
    '4d60568b': [(log, ('1.0: Grace Head IB Hash',)), (add_ib_check_if_missing,)],


    # reverted in 1.2
    # '89d903ba': [
    #     (log, ('1.0: -> 1.1: Grace Hair Texcoord Hash',)),
    #     (update_hash, ('d21f32ad',)),
    #     (log, ('+ Remapping texcoord buffer from stride 20 to 32',)),
    #     (update_buffer_element_width, (('BBBB', 'ee', 'ff', 'ee'), ('ffff', 'ee', 'ff', 'ee'), '1.1')),
    #     (log, ('+ Setting texcoord vcolor alpha to 1',)),
    #     (update_buffer_element_value, (('ffff', 'ee', 'ff', 'ee'), ('xxx1', 'xx', 'xx', 'xx'), '1.1'))
    # ],

    'd21f32ad': [
        (log, ('1.1 -> 1.2: Grace Hair Texcoord Hash',)),
        (update_hash, ('89d903ba',)),
        (log, ('+ Remapping texcoord buffer',)),
        (zzz_12_shrink_texcoord_color, ('1.2',))
    ],

    'e5e04f6f': [(log, ('1.1 -> 1.2: Grace Body Draw Hash',)),     (update_hash, ('f1cba806',))],
    '26ffa186': [
        (log, ('1.1 -> 1.2: Grace Body Position Hash',)),
        (update_hash, ('8855c5cf',)),
        (log, ('1.1 -> 1.2: Grace Body Blend Remap',)),
        (update_buffer_blend_indices, (
            '8855c5cf',
            (35, 34, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,  68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89),
            (34, 35, 80, 85, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 51, 47, 48, 49, 50, 52, 54, 53, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 66,  65, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 89, 78, 79, 81, 82, 83, 84, 86, 87, 88),
        ))
    ],
    'e536af35': [(log, ('1.1 -> 1.2: Grace Body Texcoord Hash',)), (update_hash, ('4bb45448',))],
    '0f82a13e': [
        (log, ('1.1 -> 1.2: Grace Body IB Hash',)),
        (update_hash, ('8b240678',)),
        (transfer_indexed_sections, {
            'src_indices': ['0', '42885'],
            'trg_indices': ['0', '42927'],
        })
    ],

    'e75590cb': [
        (log,                           ('1.0: Grace HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('4d60568b', 'Grace.HeadA.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7459ecf4', 'Grace.HeadA.Diffuse.2048')),
    ],
    '7459ecf4': [
        (log,                           ('1.0: Grace HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('4d60568b', 'Grace.HeadA.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e75590cb', 'Grace.HeadA.Diffuse.1024')),
    ],


    'a87d2822': [
        (log,                           ('1.0: Grace HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('94d04401', 'Grace.HairA.Diffuse.1024')),
    ],
    '94d04401': [
        (log,                           ('1.0: Grace HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a87d2822', 'Grace.HairA.Diffuse.2048')),
    ],
    '8eddd041': [
        (log,                           ('1.0: Grace HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('26bf1588', 'Grace.HairA.LightMap.1024')),
    ],
    '26bf1588': [
        (log,                           ('1.0: Grace HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8eddd041', 'Grace.HairA.LightMap.2048')),
    ],
    '3a38f6f9': [
        (log,                           ('1.0: Grace HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e1cb3739', 'Grace.HairA.MaterialMap.1024')),
    ],
    'e1cb3739': [
        (log,                           ('1.0: Grace HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3a38f6f9', 'Grace.HairA.MaterialMap.2048')),
    ],
    '846fab9a': [
        (log,                           ('1.0: Grace HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1c4079f7', 'Grace.HairA.NormalMap.1024')),
    ],
    '1c4079f7': [
        (log,                           ('1.0: Grace HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('89299f56', 'Grace.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('846fab9a', 'Grace.HairA.NormalMap.2048')),
    ],


    '6d6ac4f4': [
        (log,                           ('1.0: Grace BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('397a8aed', 'Grace.BodyA.Diffuse.1024')),
    ],
    '397a8aed': [
        (log,                           ('1.0: Grace BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6d6ac4f4', 'Grace.BodyA.Diffuse.2048')),
    ],
    '993fe3e1': [
        (log,                           ('1.0: Grace BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('59dd8899', 'Grace.BodyA.LightMap.1024')),
    ],
    '59dd8899': [
        (log,                           ('1.0: Grace BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('993fe3e1', 'Grace.BodyA.LightMap.2048')),
    ],
    'e8345f2c': [
        (log,                           ('1.0: Grace BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a6c8c203', 'Grace.BodyA.MaterialMap.1024')),
    ],
    'a6c8c203': [
        (log,                           ('1.0: Grace BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e8345f2c', 'Grace.BodyA.MaterialMap.2048')),
    ],
    '1e794b69': [
        (log,                           ('1.0: Grace BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9abd7824', 'Grace.BodyA.NormalMap.1024')),
    ],
    '9abd7824': [
        (log,                           ('1.0: Grace BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1e794b69', 'Grace.BodyA.NormalMap.2048')),
    ],
    '210b3ebf': [(log, ('1.3 -> 1.4: Grace BodyB Diffuse 2048p Hash',)), (update_hash, ('9c7057e8',))],
    '9c7057e8': [
        (log,                           ('1.4: Grace BodyB Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('ac361185', '21794bd6'), 'Grace.BodyB.Diffuse.1024')),
    ],
    '21794bd6': [(log, ('1.3 -> 1.4: Grace BodyB Diffuse 1024p Hash',)), (update_hash, ('ac361185',))],
    'ac361185': [
        (log,                           ('1.4: Grace BodyB Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('9c7057e8', '210b3ebf'), 'Grace.BodyB.Diffuse.2048')),
    ],
    '08082f5f': [
        (log,                           ('1.0: Grace BodyB LightMap 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a60162a0', 'Grace.BodyB.LightMap.1024')),
    ],
    'a60162a0': [
        (log,                           ('1.0: Grace BodyB LightMap 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('08082f5f', 'Grace.BodyB.LightMap.2048')),
    ],
    'f176398a': [
        (log,                           ('1.0: Grace BodyB MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b5b88a3f', 'Grace.BodyB.MaterialMap.1024')),
    ],
    'b5b88a3f': [
        (log,                           ('1.0: Grace BodyB MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f176398a', 'Grace.BodyB.MaterialMap.2048')),
    ],
    '06cb1413': [
        (log,                           ('1.0: Grace BodyB NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c5f703be', 'Grace.BodyB.NormalMap.1024')),
    ],
    'c5f703be': [
        (log,                           ('1.0: Grace BodyB NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('8b240678', '0f82a13e'), 'Grace.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('06cb1413', 'Grace.BodyB.NormalMap.2048')),
    ],



    # MARK: Harumasa
    '78bea30d': [(log, ('1.4 -> 1.5: Harumasa Body IB Hash',)), (update_hash, ('79679a10',))],

    '6324de38': [(log, ('1.4: Harumasa Hair IB Hash',)), (add_ib_check_if_missing,)],
    '79679a10': [(log, ('1.4: Harumasa Body IB Hash',)), (add_ib_check_if_missing,)],
    'aa7ba2dc': [(log, ('1.4: Harumasa Legs IB Hash',)), (add_ib_check_if_missing,)],
    'b0688334': [(log, ('1.4: Harumasa Face IB Hash',)), (add_ib_check_if_missing,)],


    'cafffd37': [(log, ('1.4 -> 1.5: Harumasa Body Draw Hash',)),     (update_hash, ('1fb92e46',))],
    '3fa41462': [(log, ('1.4 -> 1.5: Harumasa Body Position Hash',)), (update_hash, ('0899751e',))],
    'c0b32d17': [(log, ('1.4 -> 1.5: Harumasa Body Blend Hash',)),    (update_hash, ('347a0e9d',))],
    '95ee1030': [(log, ('1.4 -> 1.5: Harumasa Body Texcoord Hash',)), (update_hash, ('e14fbc30',))],


    '4394c0b2': [
        (log,                           ('1.4: Harumasa FaceA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('b0688334', 'Harumasa.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c5596262', 'Harumasa.FaceA.Diffuse.1024')),
    ],
    'c5596262': [
        (log,                           ('1.4: Harumasa FaceA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('b0688334', 'Harumasa.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4394c0b2', 'Harumasa.FaceA.Diffuse.2048')),
    ],

    'b8f268ee': [
        (log,                           ('1.4: Harumasa HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('6324de38', 'Harumasa.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5700ced5', 'Harumasa.HairA.Diffuse.1024')),
    ],
    'd4838b9d': [
        (log,                           ('1.4: Harumasa HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('6324de38', 'Harumasa.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a1310b4f', 'Harumasa.HairA.LightMap.1024')),
    ],
    '7217c146': [
        (log,                           ('1.4: Harumasa HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('6324de38', 'Harumasa.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c2c9ad2d', 'Harumasa.HairA.MaterialMap.1024')),
    ],
    '5700ced5': [
        (log,                           ('1.4: Harumasa HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('6324de38', 'Harumasa.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b8f268ee', 'Harumasa.HairA.Diffuse.2048')),
    ],
    'a1310b4f': [
        (log,                           ('1.4: Harumasa HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('6324de38', 'Harumasa.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d4838b9d', 'Harumasa.HairA.LightMap.2048')),
    ],
    'c2c9ad2d': [
        (log,                           ('1.4: Harumasa HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('6324de38', 'Harumasa.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7217c146', 'Harumasa.HairA.MaterialMap.2048')),
    ],

    'ba52ac92': [(log, ('1.4 -> 1.5: Harumasa BodyA Diffuse 2048p Hash',)), (update_hash, ('49f8aaf6',))],
    '49f8aaf6': [
        (log,                           ('1.4: Harumasa BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('79679a10', '78bea30d'), 'Harumasa.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('999ec526', 'e0b0c6eb'), 'Harumasa.BodyA.Diffuse.1024')),
    ],
    'cc51476a': [
        (log,                           ('1.4: Harumasa BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('79679a10', '78bea30d'), 'Harumasa.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('2b1230cf', 'Harumasa.BodyA.LightMap.1024')),
    ],
    'cd1e0187': [(log, ('1.4 -> 1.5: Harumasa BodyA MaterialMap 2048p Hash',)), (update_hash, ('6d105f7e',))],
    '6d105f7e': [
        (log,                           ('1.4: Harumasa BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('79679a10', '78bea30d'), 'Harumasa.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('c90264db', '2b0017d5'), 'Harumasa.BodyA.MaterialMap.1024')),
    ],

    'e0b0c6eb': [(log, ('1.4 -> 1.5: Harumasa BodyA Diffuse 1024p Hash',)), (update_hash, ('999ec526',))],
    '999ec526': [
        (log,                           ('1.4: Harumasa BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('79679a10', '78bea30d'), 'Harumasa.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('49f8aaf6', 'ba52ac92'), 'Harumasa.BodyA.Diffuse.2048')),
    ],
    '2b1230cf': [
        (log,                           ('1.4: Harumasa BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('79679a10', '78bea30d'), 'Harumasa.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('cc51476a', 'Harumasa.BodyA.LightMap.2048')),
    ],
    '2b0017d5': [(log, ('1.4 -> 1.5: Harumasa BodyA MaterialMap 1024p Hash',)), (update_hash, ('c90264db',))],
    'c90264db': [
        (log,                           ('1.4: Harumasa BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('79679a10', '78bea30d'), 'Harumasa.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('6d105f7e', 'cd1e0187'), 'Harumasa.BodyA.MaterialMap.2048')),
    ],

    '44d74a1a': [
        (log,                           ('1.4: Harumasa LegsA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('aa7ba2dc', 'Harumasa.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('897c74d5', 'Harumasa.LegsA.Diffuse.1024')),
    ],
    '4b4d0ff6': [
        (log,                           ('1.4: Harumasa LegsA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('aa7ba2dc', 'Harumasa.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('822ec07f', 'Harumasa.LegsA.LightMap.1024')),
    ],
    'ba8e396b': [
        (log,                           ('1.4: Harumasa LegsA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('aa7ba2dc', 'Harumasa.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bdbf66a1', 'Harumasa.LegsA.MaterialMap.1024')),
    ],
    '897c74d5': [
        (log,                           ('1.4: Harumasa LegsA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('aa7ba2dc', 'Harumasa.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('44d74a1a', 'Harumasa.LegsA.Diffuse.2048')),
    ],
    '822ec07f': [
        (log,                           ('1.4: Harumasa LegsA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('aa7ba2dc', 'Harumasa.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4b4d0ff6', 'Harumasa.LegsA.LightMap.2048')),
    ],
    'bdbf66a1': [
        (log,                           ('1.4: Harumasa LegsA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('aa7ba2dc', 'Harumasa.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ba8e396b', 'Harumasa.LegsA.MaterialMap.2048')),
    ],



    # MARK: Jane Doe
    '9268a5af': [(log, ('1.4: Jane Hair IB Hash',)), (add_ib_check_if_missing,)],
    'ba4255a5': [(log, ('1.4: Jane Body IB Hash',)), (add_ib_check_if_missing,)],
    'ef86fc9f': [(log, ('1.1: Jane Head IB Hash',)), (add_ib_check_if_missing,)],

    'c8ad344e': [
        (log, ('1.1 -> 1.2: Jane Hair Texcoord Hash',)),
        (update_hash, ('257a90d6',)),
        (log, ('+ Remapping texcoord buffer',)),
        (zzz_12_shrink_texcoord_color, ('1.2',))
    ],

    '5721e4e7': [(log, ('1.3 -> 1.4: Jane Hair Draw Hash',)),     (update_hash, ('2d06e785',)),],
    '24323bf9': [(log, ('1.3 -> 1.4: Jane Hair Position Hash',)), (update_hash, ('e7a3b7dc',)),],
    '0a10c747': [(log, ('1.3 -> 1.4: Jane Hair Blend Hash',)),    (update_hash, ('8721477f',)),],
    '257a90d6': [(log, ('1.3 -> 1.4: Jane Hair Texcoord Hash',)), (update_hash, ('acec29f8',)),],
    '7b16a708': [(log, ('1.3 -> 1.4: Jane Hair IB Hash',)),       (update_hash, ('9268a5af',)),],

    'd1aa4b85': [(log, ('1.3 -> 1.4: Jane Body Draw Hash',)),     (update_hash, ('0e1c6740',)),],
    '06f9bc49': [(log, ('1.3 -> 1.4: Jane Body Position Hash',)), (update_hash, ('10050266',)),],
    '9727a184': [(log, ('1.3 -> 1.4: Jane Body Blend Hash',)),    (update_hash, ('e27f398e',)),],
    '8b85c03e': [(log, ('1.3 -> 1.4: Jane Body Texcoord Hash',)), (update_hash, ('949549de',)),],
    'e2c0144e': [(log, ('1.3 -> 1.4: Jane Body IB Hash',)),       (update_hash, ('ba4255a5',)),],

    '689639a5': [(log, ('1.3 -> 1.4: Jane HeadA Diffuse 1024p Hash',)), (update_hash, ('d823ac80',)),],
    'd823ac80': [
        (log,                           ('1.1: Jane HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('ef86fc9f', 'Jane.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('3b75aa2c', '8974fb74'), 'Jane.HeadA.Diffuse.2048')),
    ],
    '8974fb74': [(log, ('1.3 -> 1.4: Jane HeadA Diffuse 2048p Hash',)), (update_hash, ('3b75aa2c',)),],
    '3b75aa2c': [
        (log,                           ('1.1: Jane HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('ef86fc9f', 'Jane.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('d823ac80', '689639a5'), 'Jane.HeadA.Diffuse.1024')),
    ],

    'f7ef1a53': [
        (log,                           ('1.1: Jane HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b33a9770', 'Jane.HairA.Diffuse.1024')),
    ],
    'b33a9770': [
        (log,                           ('1.1: Jane HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f7ef1a53', 'Jane.HairA.Diffuse.2048')),
    ],
    '9ec4cd4f': [
        (log,                           ('1.1: Jane HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5e12acc1', 'Jane.HairA.LightMap.1024')),
    ],
    '5e12acc1': [
        (log,                           ('1.1: Jane HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9ec4cd4f', 'Jane.HairA.LightMap.2048')),
    ],
    '5e34e275': [
        (log,                           ('1.1: Jane HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('40fca454', 'Jane.HairA.MaterialMap.1024')),
    ],
    '40fca454': [
        (log,                           ('1.1: Jane HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5e34e275', 'Jane.HairA.MaterialMap.2048')),
    ],
    '4aa12b36': [
        (log,                           ('1.1: Jane HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f0aded31', 'Jane.HairA.NormalMap.1024')),
    ],
    'f0aded31': [
        (log,                           ('1.1: Jane HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('9268a5af', '7b16a708'), 'Jane.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4aa12b36', 'Jane.HairA.NormalMap.2048')),
    ],

    'd1f56c7d': [
        (log,                           ('1.1: Jane BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e62ae3b5', 'Jane.BodyA.Diffuse.1024')),
    ],
    'e62ae3b5': [
        (log,                           ('1.1: Jane BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d1f56c7d', 'Jane.BodyA.Diffuse.2048')),
    ],
    '3087f82a': [
        (log,                           ('1.1: Jane BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('52fa9861', 'Jane.BodyA.LightMap.1024')),
    ],
    '52fa9861': [
        (log,                           ('1.1: Jane BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3087f82a', 'Jane.BodyA.LightMap.2048')),
    ],
    '99eae42e': [
        (log,                           ('1.1: Jane BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5dce2408', 'Jane.BodyA.MaterialMap.1024')),
    ],
    '5dce2408': [
        (log,                           ('1.1: Jane BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('99eae42e', 'Jane.BodyA.MaterialMap.2048')),
    ],
    '0165f71c': [
        (log,                           ('1.1: Jane BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('387dfc9f', 'Jane.BodyA.NormalMap.1024')),
    ],
    '387dfc9f': [
        (log,                           ('1.1: Jane BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('ba4255a5', 'e2c0144e'), 'Jane.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0165f71c', 'Jane.BodyA.NormalMap.2048')),
    ],



    # MARK: Koleda
    '242a8d48': [(log, ('1.0: Koleda Hair IB Hash',)), (add_ib_check_if_missing,)],
    '3afb3865': [(log, ('1.0: Koleda Body IB Hash',)), (add_ib_check_if_missing,)],
    '0e74656e': [(log, ('1.0: Koleda Head IB Hash',)), (add_ib_check_if_missing,)],
    

    '1a9b182a': [
        (log,            ('1.2 -> 1.3: Koleda Hair Texcoord Hash',)),
        (update_hash,    ('e35571a9',)),
        (log,            ('+ Remapping texcoord buffer',)),
        (zzz_13_remap_texcoord, (
            '13_koleda_hair',
            ('4B','2e','2f','2e'),
            ('4B','2f','2f','2f')
        )),
    ],
    'e3021a32': [
        (log,            ('1.2 -> 1.3: Koleda Body Texcoord Hash',)),
        (update_hash,    ('38b31082',)),
        (log,            ('+ Remapping texcoord buffer',)),
        (zzz_13_remap_texcoord, (
            '13_koleda_body',
            ('4B','2e','2f','2e'),
            ('4B','2f','2f','2f')
        )),
    ],

    'f1045670': [
        (log,                           ('1.0: Koleda HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('0e74656e', 'Koleda.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('200db5c4', 'Koleda.HeadA.Diffuse.2048')),
    ],
    '200db5c4': [
        (log,                           ('1.0: Koleda HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('0e74656e', 'Koleda.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f1045670', 'Koleda.HeadA.Diffuse.1024')),
    ],


    'e8e89f00': [
        (log,                           ('1.0: Koleda HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('242a8d48', 'Koleda.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b0046e5a', 'Koleda.HairA.Diffuse.1024')),
    ],
    'b0046e5a': [
        (log,                           ('1.0: Koleda HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('242a8d48', 'Koleda.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e8e89f00', 'Koleda.HairA.Diffuse.2048')),
    ],
    '8042506d': [
        (log,                           ('1.0: Koleda HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('242a8d48', 'Koleda.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('144ab293', 'Koleda.HairA.LightMap.1024')),
    ],
    '144ab293': [
        (log,                           ('1.0: Koleda HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('242a8d48', 'Koleda.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8042506d', 'Koleda.HairA.LightMap.2048')),
    ],
    'd1aac666': [
        (log,                           ('1.0: Koleda HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('242a8d48', 'Koleda.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7a46b52a', 'Koleda.HairA.NormalMap.1024')),
    ],
    '7a46b52a': [
        (log,                           ('1.0: Koleda HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('242a8d48', 'Koleda.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d1aac666', 'Koleda.HairA.NormalMap.2048')),
    ],


    '337fd6a2': [
        (log,                           ('1.0: Koleda BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ce10237d', 'Koleda.BodyA.Diffuse.1024')),
    ],
    'ce10237d': [
        (log,                           ('1.0: Koleda BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('337fd6a2', 'Koleda.BodyA.Diffuse.2048')),
    ],
    '78e0f9f5': [
        (log,                           ('1.0: Koleda BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('db58787e', 'Koleda.BodyA.LightMap.1024')),
    ],
    'db58787e': [
        (log,                           ('1.0: Koleda BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('78e0f9f5', 'Koleda.BodyA.LightMap.2048')),
    ],
    '6f34885f': [
        (log,                           ('1.0: Koleda BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('02e6cb95', 'Koleda.BodyA.MaterialMap.1024')),
    ],
    '02e6cb95': [
        (log,                           ('1.0: Koleda BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6f34885f', 'Koleda.BodyA.MaterialMap.2048')),
    ],
    'e71d134f': [
        (log,                           ('1.0: Koleda BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0914d3d3', 'Koleda.BodyA.NormalMap.1024')),
    ],
    '0914d3d3': [
        (log,                           ('1.0: Koleda BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('3afb3865', 'Koleda.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('e71d134f', 'Koleda.BodyA.NormalMap.2048')),
    ],


    # MARK: Lighter
    '542b8aa9': [(log, ('1.3: Lighter Hair IB Hash',)),    (add_ib_check_if_missing,)],
    '8899e0fd': [(log, ('1.3: Lighter Body IB Hash',)),    (add_ib_check_if_missing,)],
    '018b03f0': [(log, ('1.3: Lighter Arm IB Hash',)),     (add_ib_check_if_missing,)],

    '039f30cf': [(log, ('1.3 -> 1.4: Lighter Face IB Hash',)), (update_hash, ('dcc7bb78',))],
    'dcc7bb78': [(log, ('1.3: Lighter Face IB Hash',)),        (add_ib_check_if_missing,)],

    '0baec6b7': [(log, ('1.3 -> 1.4: Lighter Body Position Hash',)), (update_hash, ('5e461440',))],
    '710bca71': [(log, ('1.3 -> 1.4: Lighter Body Texcoord Hash',)), (update_hash, ('25ad7289',))],
    'af2e48a6': [(log, ('1.3 -> 1.4: Lighter Arm Texcoord Hash',)),  (update_hash, ('88aecee2',))],

    '5e461440': [(log, ('1.5 -> 1.6: Lighter Body Position Hash',)),  (update_hash, ('f6bbabb5',))],
    '25ad7289': [(log, ('1.5 -> 1.6: Lighter Body Texcoord Hash',)),  (update_hash, ('e1ae7f38',))],

    '8ec33dd0': [
        (log,                           ('1.3: Lighter FaceA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('dcc7bb78', '039f30cf'), 'Lighter.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4524e91a', 'Lighter.FaceA.Diffuse.2048')),
    ],
    '4524e91a': [
        (log,                           ('1.3: Lighter FaceA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('dcc7bb78', '039f30cf'), 'Lighter.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8ec33dd0', 'Lighter.FaceA.Diffuse.1024')),
    ],

    '1cd2d442': [
        (log,                           ('1.3: Lighter HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('542b8aa9', 'Lighter.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c5d60a1d', 'Lighter.HairA.Diffuse.2048')),
    ],
    '62ec7f01': [
        (log,                           ('1.3: Lighter HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('542b8aa9', 'Lighter.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6d3f91bc', 'Lighter.HairA.LightMap.2048')),
    ],
    '8687f7b8': [
        (log,                           ('1.3: Lighter HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('542b8aa9', 'Lighter.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d5ba9ea6', 'Lighter.HairA.MaterialMap.2048')),
    ],
    'c5d60a1d': [
        (log,                           ('1.3: Lighter HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('542b8aa9', 'Lighter.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1cd2d442', 'Lighter.HairA.Diffuse.1024')),
    ],
    '6d3f91bc': [
        (log,                           ('1.3: Lighter HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('542b8aa9', 'Lighter.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('62ec7f01', 'Lighter.HairA.LightMap.1024')),
    ],
    'd5ba9ea6': [
        (log,                           ('1.3: Lighter HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('542b8aa9', 'Lighter.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8687f7b8', 'Lighter.HairA.MaterialMap.1024')),
    ],

    'be46890b': [
        (log,                           ('1.3: Lighter BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('8899e0fd', 'Lighter.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5ed96bf2', 'Lighter.BodyA.Diffuse.2048')),
    ],
    '5b828635': [
        (log,                           ('1.3: Lighter BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('8899e0fd', 'Lighter.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('da6f4dc0', 'Lighter.BodyA.LightMap.2048')),
    ],
    '65f3bb7c': [
        (log,                           ('1.3: Lighter BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('8899e0fd', 'Lighter.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('94aebd7e', 'Lighter.BodyA.MaterialMap.2048')),
    ],
    '5ed96bf2': [
        (log,                           ('1.3: Lighter BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('8899e0fd', 'Lighter.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('be46890b', 'Lighter.BodyA.Diffuse.1024')),
    ],
    'da6f4dc0': [
        (log,                           ('1.3: Lighter BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('8899e0fd', 'Lighter.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5b828635', 'Lighter.BodyA.LightMap.1024')),
    ],
    '94aebd7e': [
        (log,                           ('1.3: Lighter BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('8899e0fd', 'Lighter.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('65f3bb7c', 'Lighter.BodyA.MaterialMap.1024')),
    ],

    '6506987b': [
        (log,                           ('1.3: Lighter ArmA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('018b03f0', 'Lighter.Arm.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8b854866', 'Lighter.ArmA.Diffuse.2048')),
    ],
    '939a2e18': [
        (log,                           ('1.3: Lighter ArmA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('018b03f0', 'Lighter.Arm.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('547cbcd8', 'Lighter.ArmA.LightMap.2048')),
    ],
    '1684d3e4': [
        (log,                           ('1.3: Lighter ArmA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('018b03f0', 'Lighter.Arm.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3617c303', 'Lighter.ArmA.MaterialMap.2048')),
    ],
    '8b854866': [
        (log,                           ('1.3: Lighter ArmA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('018b03f0', 'Lighter.Arm.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6506987b', 'Lighter.ArmA.Diffuse.1024')),
    ],
    '547cbcd8': [
        (log,                           ('1.3: Lighter ArmA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('018b03f0', 'Lighter.Arm.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('939a2e18', 'Lighter.ArmA.LightMap.1024')),
    ],
    '3617c303': [
        (log,                           ('1.3: Lighter ArmA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('018b03f0', 'Lighter.Arm.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1684d3e4', 'Lighter.ArmA.MaterialMap.1024')),
    ],



    # MARK: Lucy
    '69ad9d08': [(log, ('1.3: Lucy Hair IB Hash',)),     (add_ib_check_if_missing,)],
    '272dd7f6': [(log, ('1.0: Lucy Snout IB Hash',)),    (add_ib_check_if_missing,)],
    '9b6370f6': [(log, ('1.0: Lucy Belt IB Hash',)),     (add_ib_check_if_missing,)],
    'be5f4c7d': [(log, ('1.3: Lucy Body IB Hash',)),     (add_ib_check_if_missing,)],
    '1fe6e084': [(log, ('1.0: Lucy RedCloth IB Hash',)), (add_ib_check_if_missing,)],
    'a0ed04de': [(log, ('1.0: Lucy Helmet IB Hash',)),   (add_ib_check_if_missing,)],
    'df3e3965': [(log, ('1.3: Lucy Head IB Hash',)),     (add_ib_check_if_missing,)],

    '5315f036': [(log, ('1.2 -> 1.3: Lucy Hair Blend Hash',)),    (update_hash, ('a37c7537',))],
    '751e21a5': [(log, ('1.2 -> 1.3: Lucy Hair Texcoord Hash',)), (update_hash, ('c8810832',))],
    '198e99d7': [
        (log, ('1.2 -> 1.3: Lucy Hair IB Hash',)),
        (update_hash, ('69ad9d08',)),
        (transfer_indexed_sections, {
            'src_indices': ['0', '-1'],
            'trg_indices': ['0', '5253'],
        })
    ],

    '5da9dafc': [(log, ('1.2 -> 1.3: Lucy Body Position Hash',)), (update_hash, ('246b93e2',))],
    'b94b02e8': [(log, ('1.2 -> 1.3: Lucy Body Blend Hash',)),    (update_hash, ('66948a0f',))],
    '00f11ea6': [(log, ('1.2 -> 1.3: Lucy Body Texcoord Hash',)), (update_hash, ('f60dbb9e',))],
    'e0ad50ed': [(log, ('1.2 -> 1.3: Lucy Body IB Hash',)),       (update_hash, ('be5f4c7d',))],

    'fca15ccb': [(log, ('1.2 -> 1.3: Lucy Head IB Hash',)),       (update_hash, ('df3e3965',))],


    '483b418a': [(log, ('1.2 -> 1.3: Lucy HeadA Diffuse 1024p Hash',)), (update_hash, ('2578d35b',))],
    '2a6df536': [(log, ('1.2 -> 1.3: Lucy HeadA Diffuse 1024p Hash',)), (update_hash, ('4e2d5baa',))],

    '2578d35b': [
        (log,                           ('1.3: Lucy HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('df3e3965', 'fca15ccb'), 'Lucy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('4e2d5baa', '2a6df536'), 'Lucy.HeadA.Diffuse.2048')),
    ],
    '4e2d5baa': [
        (log,                           ('1.3: Lucy HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('df3e3965', 'fca15ccb'), 'Lucy.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('2578d35b', '483b418a'), 'Lucy.HeadA.Diffuse.1024')),
    ],


    'b50eb71c': [(log, ('1.2 -> 1.3: Lucy HairA, SnoutA, BeltA Diffuse 1024p Hash',)),     (update_hash, ('753baa45',))],
    'd1241cfc': [(log, ('1.2 -> 1.3: Lucy HairA, SnoutA, BeltA MaterialMap 1024p Hash',)), (update_hash, ('368f931c',))],

    'aa513afa': [(log, ('1.2 -> 1.3: Lucy HairA, SnoutA, BeltA Diffuse 2048p Hash',)),     (update_hash, ('0fa60fe1',))],
    '919b608c': [(log, ('1.2 -> 1.3: Lucy HairA, SnoutA, BeltA MaterialMap 2048p Hash',)), (update_hash, ('068aba7f',))],

    '0fa60fe1': [
        (log,                           ('1.3: Lucy HairA, SnoutA, BeltA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   (('753baa45', 'b50eb71c'), 'Lucy.HairA.Diffuse.1024')),
    ],
    '753baa45': [
        (log,                           ('1.3: Lucy HairA, SnoutA, BeltA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   (('0fa60fe1', 'aa513afa'), 'Lucy.HairA.Diffuse.2048')),
    ],
    '1a3b30ba': [
        (log,                           ('1.0: Lucy HairA, SnoutA, BeltA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('810c0878', 'Lucy.HairA.LightMap.1024')),
    ],
    '810c0878': [
        (log,                           ('1.0: Lucy HairA, SnoutA, BeltA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('1a3b30ba', 'Lucy.HairA.LightMap.2048')),
    ],
    '068aba7f': [
        (log,                           ('1.3: Lucy HairA, SnoutA, BeltA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   (('368f931c', 'd1241cfc'), 'Lucy.HairA.MaterialMap.1024')),
    ],
    '368f931c': [
        (log,                           ('1.3: Lucy HairA, SnoutA, BeltA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   (('068aba7f', '919b608c'), 'Lucy.HairA.MaterialMap.2048')),
    ],
    'edcb9661': [
        (log,                           ('1.0: Lucy HairA, SnoutA, BeltA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('9114c7c7', 'Lucy.HairA.NormalMap.1024')),
    ],
    '9114c7c7': [
        (log,                           ('1.0: Lucy HairA, SnoutA, BeltA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('edcb9661', 'Lucy.HairA.NormalMap.2048')),
    ],
    '474c7aa2': [
        (log,                           ('1.0: Lucy BodyA, RedClothA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('f810e7ac', 'Lucy.BodyA.Diffuse.1024')),
    ],
    'f810e7ac': [
        (log,                           ('1.0: Lucy BodyA, RedClothA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('474c7aa2', 'Lucy.BodyA.Diffuse.2048')),
    ],
    '855d9fa3': [
        (log,                           ('1.0: Lucy BodyA, RedClothA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('e89f7814', 'Lucy.BodyA.LightMap.1024')),
    ],
    'e89f7814': [
        (log,                           ('1.0: Lucy BodyA, RedClothA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('855d9fa3', 'Lucy.BodyA.LightMap.2048')),
    ],
    '1fd24fd8': [
        (log,                           ('1.0: Lucy BodyA, RedClothA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('86ca6cfd', 'Lucy.BodyA.MaterialMap.1024')),
    ],
    '86ca6cfd': [
        (log,                           ('1.0: Lucy BodyA, RedClothA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('1fd24fd8', 'Lucy.BodyA.MaterialMap.2048')),
    ],
    '463b4f55': [
        (log,                           ('1.0: Lucy BodyA, RedClothA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('1711cafd', 'Lucy.BodyA.NormalMap.1024')),
    ],
    '1711cafd': [
        (log,                           ('1.0: Lucy BodyA, RedClothA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('463b4f55', 'Lucy.BodyA.NormalMap.2048')),
    ],
    'a0be0ed3': [
        (log,                           ('1.0: Lucy HelmetA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('919ab7e5', 'Lucy.HelmetA.Diffuse.1024')),
    ],
    '919ab7e5': [
        (log,                           ('1.0: Lucy HelmetA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a0be0ed3', 'Lucy.HelmetA.Diffuse.2048')),
    ],
    '8d9a16c7': [
        (log,                           ('1.0: Lucy HelmetA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6a8fca92', 'Lucy.HelmetA.LightMap.1024')),
    ],
    '6a8fca92': [
        (log,                           ('1.0: Lucy HelmetA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8d9a16c7', 'Lucy.HelmetA.LightMap.2048')),
    ],
    'b3013a33': [
        (log,                           ('1.0: Lucy HelmetA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4227db77', 'Lucy.HelmetA.MaterialMap.1024')),
    ],
    '4227db77': [
        (log,                           ('1.0: Lucy HelmetA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b3013a33', 'Lucy.HelmetA.MaterialMap.2048')),
    ],
    'ca5fd23a': [
        (log,                           ('1.0: Lucy HelmetA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f4d44970', 'Lucy.HelmetA.NormalMap.1024')),
    ],
    'f4d44970': [
        (log,                           ('1.0: Lucy HelmetA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('a0ed04de', 'Lucy.Helmet.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ca5fd23a', 'Lucy.HelmetA.NormalMap.2048')),
    ],



    # MARK: Lycaon
    '060bc1ad': [(log, ('1.0: Lycaon Hair IB Hash',)),              (add_ib_check_if_missing,)],
    '395572dc': [(log, ('1.3 -> 1.4: Lycaon Hair Texcoord Hash',)), (update_hash, ('b092c043',))],
    
    '25196b7a': [(log, ('1.3 -> 1.4: Lycaon Body IB Hash',)), (update_hash, ('6749b6e7',))],
    '6749b6e7': [(log, ('1.0: Lycaon Body IB Hash',)),        (add_ib_check_if_missing,)],
    
    '2a340ed5': [(log, ('1.3 -> 1.4: Lycaon Body Draw Hash',)),     (update_hash, ('25418598',))],
    '949e688a': [(log, ('1.3 -> 1.4: Lycaon Body Texcoord Hash',)), (update_hash, ('b950fda5',))],
    'b68056b4': [
        (log, ('1.3 -> 1.4: Lycaon Body Position Hash',)),
        (update_hash, ('8c7775ae',)),
        (log, ('1.3 -> 1.4: Lycaon Body Blend Remap',)),
        (update_buffer_blend_indices, (
            '8c7775ae',
            (50, 51, 89, 90,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110),
            (51, 50, 90, 89, 669, 669, 669, 669, 669, 669, 669, 669, 669,  98,  99, 100, 101)
        ))
    ],
    'a485180e': [
        (log,                         ('1.3 -> 1.4: Lycaon Body Blend Remap',)),
        (update_hash,                 ('f2d1a929',)),
        (update_buffer_blend_indices, (
            'f2d1a929',
            (50, 51, 89, 90,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110),
            (51, 50, 90, 89, 669, 669, 669, 669, 669, 669, 669, 669, 669,  98,  99, 100, 101)
        )),
    ],

    '5e710f36': [(log, ('1.0: Lycaon Mask IB Hash',)), (add_ib_check_if_missing,)],
    '22a1347b': [(log, ('1.0: Lycaon Legs IB Hash',)), (add_ib_check_if_missing,)],
    '6ffdfccb': [(log, ('1.6: Lycaon Head IB Hash',)), (add_ib_check_if_missing,)],

    '7074f97e': [(log, ('1.5 -> 1.6: Lycaon Head Draw Hash',)),     (update_hash, ('44277f65',))],
    '4a666a39': [(log, ('1.5 -> 1.6: Lycaon Head Position Hash',)), (update_hash, ('7e35ec22',))],
    'c862a611': [(log, ('1.5 -> 1.6: Lycaon Head Blend Hash',)),    (update_hash, ('e2d4c532',))],
    '6902f441': [(log, ('1.? -> 1.?: Lycaon Head Texcoord Hash',)), (update_hash, ('b1edaf35',))],
    'b1edaf35': [(log, ('1.? -> 1.6: Lycaon Head Texcoord Hash',)), (update_hash, ('3adaebb3',))],
    '7341e07b': [(log, ('1.5 -> 1.6: Lycaon Head IB Hash',)),       (update_hash, ('6ffdfccb',))],

    '4f098897': [(log, ('1.5 -> 1.6: Lycaon Head Diffuse 1024p Hash',)), (update_hash, ('2cc208a7',))],
    '2cc208a7': [
        (log,                           ('1.0: Lycaon HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('6ffdfccb', '7341e07b'), 'Lycaon.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('7077ebb1', 'd14f3284'), 'Lycaon.HeadA.Diffuse.2048')),
    ],
    'd14f3284': [(log, ('1.5 -> 1.6: Lycaon Head Diffuse 2048p Hash',)), (update_hash, ('7077ebb1',))],
    '7077ebb1': [
        (log,                           ('1.0: Lycaon HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('6ffdfccb', '7341e07b'), 'Lycaon.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('2cc208a7', '4f098897'), 'Lycaon.HeadA.Diffuse.1024')),
    ],

    '61aaace5': [
        (log,                           ('1.0: Lycaon HairA, MaskA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('3bd1b7e6', 'Lycaon.HairA.Diffuse.1024')),
    ],
    '3bd1b7e6': [
        (log,                           ('1.0: Lycaon HairA, MaskA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('61aaace5', 'Lycaon.HairA.Diffuse.2048')),
    ],
    '3d6eb388': [(log, ('1.3 -> 1.4: Lycaon HairA, MaskA LightMap 2048p Hash',)), (update_hash, ('04d061fe',))],
    '04d061fe': [
        (log,                           ('1.4: Lycaon HairA, MaskA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   (('4d878953', '4d4e8986'), 'Lycaon.HairA.LightMap.1024')),
    ],
    '4d4e8986': [(log, ('1.3 -> 1.4: Lycaon HairA, MaskA LightMap 1024p Hash',)), (update_hash, ('4d878953',))],
    '4d878953': [
        (log,                           ('1.4: Lycaon HairA, MaskA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   (('04d061fe', '3d6eb388'), 'Lycaon.HairA.LightMap.2048')),
    ],
    '02bfcc69': [
        (log,                           ('1.0: Lycaon HairA, MaskA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('ba0f8320', 'Lycaon.HairA.MaterialMap.1024')),
    ],
    'ba0f8320': [
        (log,                           ('1.0: Lycaon HairA, MaskA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('02bfcc69', 'Lycaon.HairA.MaterialMap.2048')),
    ],
    '5817e801': [
        (log,                           ('1.0: Lycaon HairA, MaskA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('71925b2f', 'Lycaon.HairA.NormalMap.1024')),
    ],
    '71925b2f': [
        (log,                           ('1.0: Lycaon HairA, MaskA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('5817e801', 'Lycaon.HairA.NormalMap.2048')),
    ],

    '7169ec86': [
        (log,                           ('1.0: Lycaon BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('82ad0c28', 'Lycaon.BodyA.Diffuse.1024')),
    ],
    '82ad0c28': [
        (log,                           ('1.0: Lycaon BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7169ec86', 'Lycaon.BodyA.Diffuse.2048')),
    ],
    '565aa8be': [(log, ('1.3 -> 1.4: Lycaon Body LightMap 2048p Hash',)), (update_hash, ('814db5bf',))],
    '814db5bf': [
        (log,                           ('1.0: Lycaon BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('122c655e', '7ea75154'), 'Lycaon.BodyA.LightMap.1024')),
    ],
    '7ea75154': [(log, ('1.3 -> 1.4: Lycaon Body LightMap 1024p Hash',)), (update_hash, ('122c655e',))],
    '122c655e': [
        (log,                           ('1.0: Lycaon BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('814db5bf', '565aa8be'), 'Lycaon.BodyA.LightMap.2048')),
    ],
    '5a321eae': [
        (log,                           ('1.0: Lycaon BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7cca7d7e', 'Lycaon.BodyA.MaterialMap.1024')),
    ],
    '7cca7d7e': [
        (log,                           ('1.0: Lycaon BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5a321eae', 'Lycaon.BodyA.MaterialMap.2048')),
    ],
    'c8fd1702': [
        (log,                           ('1.0: Lycaon BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bac2b2e2', 'Lycaon.BodyA.NormalMap.1024')),
    ],
    'bac2b2e2': [
        (log,                           ('1.0: Lycaon BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('6749b6e7', '25196b7a'), 'Lycaon.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c8fd1702', 'Lycaon.BodyA.NormalMap.2048')),
    ],

    'd947066b': [
        (log,                           ('1.0: Lycaon LegsA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('89bd4d58', 'Lycaon.LegsA.Diffuse.1024')),
    ],
    '89bd4d58': [
        (log,                           ('1.0: Lycaon LegsA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d947066b', 'Lycaon.LegsA.Diffuse.2048')),
    ],
    '072e6786': [
        (log,                           ('1.0: Lycaon LegsA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3dfdab95', 'Lycaon.LegsA.LightMap.1024')),
    ],
    '3dfdab95': [
        (log,                           ('1.0: Lycaon LegsA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('072e6786', 'Lycaon.LegsA.LightMap.2048')),
    ],
    '4a4ea6dc': [
        (log,                           ('1.0: Lycaon LegsA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('288e7fbd', 'Lycaon.LegsA.MaterialMap.1024')),
    ],
    '288e7fbd': [
        (log,                           ('1.0: Lycaon LegsA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4a4ea6dc', 'Lycaon.LegsA.MaterialMap.2048')),
    ],
    '72f53876': [
        (log,                           ('1.0: Lycaon LegsA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a6efc854', 'Lycaon.LegsA.NormalMap.1024')),
    ],
    'a6efc854': [
        (log,                           ('1.0: Lycaon LegsA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('22a1347b', 'Lycaon.Legs.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('72f53876', 'Lycaon.LegsA.NormalMap.2048')),
    ],



    # MARK: Miyabi
    '4faabaac': [(log, ('1.4: Miyabi Hair IB Hash',)),   (add_ib_check_if_missing,)],
    '981c1a1e': [(log, ('1.4: Miyabi Body IB Hash',)),   (add_ib_check_if_missing,)],
    'd8003df3': [(log, ('1.4: Miyabi Legs IB Hash',)),   (add_ib_check_if_missing,)],
    'dbd59d30': [(log, ('1.4: Miyabi Face IB Hash',)),   (add_ib_check_if_missing,)],

    '1d487fd5': [
        (log,                           ('1.4: Miyabi FaceA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('dbd59d30', 'Miyabi.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('92599e94', 'Miyabi.FaceA.Diffuse.1024')),
    ],
    '92599e94': [
        (log,                           ('1.4: Miyabi FaceA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('dbd59d30', 'Miyabi.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1d487fd5', 'Miyabi.FaceA.Diffuse.2048')),
    ],

    '012e84e9': [
        (log,                           ('1.4: Miyabi HairA, LegsA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('ed6b94f7', 'Miyabi.HairA.Diffuse.1024')),
    ],
    'a6ea6d83': [
        (log,                           ('1.4: Miyabi HairA, LegsA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('8b5708f4', 'Miyabi.HairA.LightMap.1024')),
    ],
    'd5462e37': [
        (log,                           ('1.4: Miyabi HairA, LegsA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('a84d9003', 'Miyabi.HairA.MaterialMap.1024')),
    ],
    'ed6b94f7': [
        (log,                           ('1.4: Miyabi HairA, LegsA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('012e84e9', 'Miyabi.HairA.Diffuse.2048')),
    ],
    '8b5708f4': [
        (log,                           ('1.4: Miyabi HairA, LegsA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('a6ea6d83', 'Miyabi.HairA.LightMap.2048')),
    ],
    'a84d9003': [
        (log,                           ('1.4: Miyabi HairA, LegsA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('d5462e37', 'Miyabi.HairA.MaterialMap.2048')),
    ],

    '09a2bbd1': [
        (log,                           ('1.4: Miyabi BodyA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('1a3644e7', 'Miyabi.BodyA.Diffuse.1024')),
    ],
    'fd289380': [
        (log,                           ('1.4: Miyabi BodyA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('0492f64a', 'Miyabi.BodyA.LightMap.1024')),
    ],
    '450770fd': [
        (log,                           ('1.4: Miyabi BodyA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('168b1df9', 'Miyabi.BodyA.MaterialMap.1024')),
    ],
    '1a3644e7': [
        (log,                           ('1.4: Miyabi BodyA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('09a2bbd1', 'Miyabi.BodyA.Diffuse.2048')),
    ],
    '0492f64a': [
        (log,                           ('1.4: Miyabi BodyA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('fd289380', 'Miyabi.BodyA.LightMap.2048')),
    ],
    '168b1df9': [
        (log,                           ('1.4: Miyabi BodyA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('450770fd', 'Miyabi.BodyA.MaterialMap.2048')),
    ],



    # MARK: Nekomata
    'da11fd85': [(log, ('1.0: Nekomata Hair IB Hash',)),   (add_ib_check_if_missing,)],
    '26a487ff': [(log, ('1.0: Nekomata Body IB Hash',)),   (add_ib_check_if_missing,)],
    '74688145': [(log, ('1.0: Nekomata Swords IB Hash',)), (add_ib_check_if_missing,)],
    '37119851': [(log, ('1.0: Nekomata Head IB Hash',)),   (add_ib_check_if_missing,)],
    
    
    'd9370c84': [(log, ('1.0 -> 1.1: Nekomata HeadA Diffuse 1024p Hash',)), (update_hash, ('0834f635',))],
    '0834f635': [
        (log,                           ('1.1: Nekomata HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('37119851', 'Nekomata.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('ba411d22', 'fed3abbe'), 'Nekomata.HeadA.Diffuse.2048')),
    ],

    'fed3abbe': [(log, ('1.0 -> 1.1: Nekomata HeadA Diffuse 2048p Hash',)), (update_hash, ('ba411d22',))],
    'ba411d22': [
        (log,                           ('1.1: Nekomata HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('37119851', 'Nekomata.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('0834f635', 'd9370c84'), 'Nekomata.HeadA.Diffuse.1024')),
    ],


    '2c317dda': [(log, ('1.0 -> 1.1: Nekomata Body Position Hash',)),  (update_hash, ('eaad1408',))],
    'b5a4c084': [(log, ('1.0 -> 1.1: Nekomata Body Texcoord Hash',)),  (update_hash, ('f589a51f',))],

    '6abb714e': [(log, ('1.0 -> 1.1: Nekomata Swords Position Hash',)), (update_hash, ('3c4015fd',))],
    '70f4875e': [(log, ('1.0 -> 1.1: Nekomata Swords Texcoord Hash',)), (update_hash, ('2a4f8c9e',))],


    '25f3ae9b': [
        (log,                           ('1.0: Nekomata HairA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('aed3d8bd', 'Nekomata.HairA.Diffuse.1024')),
    ],
    'aed3d8bd': [
        (log,                           ('1.0: Nekomata HairA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('25f3ae9b', 'Nekomata.HairA.Diffuse.2048')),
    ],
    '548c7f7d': [
        (log,                           ('1.0: Nekomata HairA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('f8accad8', 'Nekomata.HairA.LightMap.1024')),
    ],
    'f8accad8': [
        (log,                           ('1.0: Nekomata HairA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('548c7f7d', 'Nekomata.HairA.LightMap.2048')),
    ],
    '4ca5efc6': [
        (log,                           ('1.0: Nekomata HairA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('0c22352c', 'Nekomata.HairA.MaterialMap.1024')),
    ],
    '0c22352c': [
        (log,                           ('1.0: Nekomata HairA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('4ca5efc6', 'Nekomata.HairA.MaterialMap.2048')),
    ],
    '799eb07d': [
        (log,                           ('1.0: Nekomata HairA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('c936ea68', 'Nekomata.HairA.NormalMap.1024')),
    ],
    'c936ea68': [
        (log,                           ('1.0: Nekomata HairA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('799eb07d', 'Nekomata.HairA.NormalMap.2048')),
    ],
    'd3f67c0d': [
        (log,                           ('1.0: -> 1.1: Nekomata HairB, BodyA, SwordsA Diffuse 2048p Hash',)),
        (update_hash,                   ('207b8e63',)),
    ],
    '207b8e63': [
        (log,                           ('1.0: Nekomata HairB, BodyA, SwordsA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   (('60687646', '37d3154d'), 'Nekomata.HairB.Diffuse.1024')),
    ],
    '37d3154d': [
        (log,                           ('1.0: -> 1.1: Nekomata HairB, BodyA, SwordsA Diffuse 1024p Hash',)),
        (update_hash,                   ('60687646',)),
    ],
    '60687646': [
        (log,                           ('1.1 Nekomata HairB, BodyA, SwordsA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   (('207b8e63', 'd3f67c0d'), 'Nekomata.HairB.Diffuse.2048')),
    ],
    'fc53fc6f': [
        (log,                           ('1.0: Nekomata HairB, BodyA, SwordsA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('4f3f7df0', 'Nekomata.HairB.LightMap.1024')),
    ],
    '4f3f7df0': [
        (log,                           ('1.0: Nekomata HairB, BodyA, SwordsA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('fc53fc6f', 'Nekomata.HairB.LightMap.2048')),
    ],
    'f26828bd': [
        (log,                           ('1.0: Nekomata HairB, BodyA, SwordsA MaterialMap 2048p Hash',)),
        (update_hash,                   ('b3286755',)),
    ],
    'b3286755': [
        (log,                           ('1.1: Nekomata HairB, BodyA, SwordsA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   (('a5529690', '424da647'), 'Nekomata.HairB.MaterialMap.1024')),
    ],
    '424da647': [
        (log,                           ('1.0 -> 1.1: Nekomata HairB, BodyA, SwordsA MaterialMap 1024p Hash',)),
        (update_hash,                   ('a5529690',)),
    ],
    'a5529690': [
        (log,                           ('1.1: Nekomata HairB, BodyA, SwordsA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   (('b3286755', 'f26828bd'), 'Nekomata.HairB.MaterialMap.2048')),
    ],
    'ecaef71c': [
        (log,                           ('1.0: Nekomata HairB, BodyA, SwordsA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('c1933b38', 'Nekomata.HairB.NormalMap.1024')),
    ],
    'c1933b38': [
        (log,                           ('1.0: Nekomata HairB, BodyA, SwordsA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('ecaef71c', 'Nekomata.HairB.NormalMap.2048')),
    ],



    # MARK: Nicole
    '6847bbbd': [(log, ('1.0: Nicole Hair IB Hash',)),    (add_ib_check_if_missing,)],
    '5a4c1ef3': [(log, ('1.0: Nicole Body IB Hash',)),    (add_ib_check_if_missing,)],
    '7435fc0e': [(log, ('1.0: Nicole Head IB Hash',)),    (add_ib_check_if_missing,)],


    '6abd3dd3': [
        (log,                           ('1.0: Nicole HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('7435fc0e', 'Nicole.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d1e84a34', 'Nicole.HeadA.Diffuse.2048')),
    ],
    'd1e84a34': [
        (log,                           ('1.0: Nicole HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('7435fc0e', 'Nicole.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6abd3dd3', 'Nicole.HeadA.Diffuse.1024')),
    ],


    '6d3868f9': [
        (log,                           ('1.0: Nicole HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('6847bbbd', 'Nicole.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7a45adcd', 'Nicole.HairA.Diffuse.1024')),
    ],
    '7a45adcd': [
        (log,                           ('1.0: Nicole HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('6847bbbd', 'Nicole.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6d3868f9', 'Nicole.HairA.Diffuse.2048')),
    ],
    '1dfd9e16': [
        (log,                           ('1.0: Nicole HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('6847bbbd', 'Nicole.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9adc04ed', 'Nicole.HairA.LightMap.1024')),
    ],
    '9adc04ed': [
        (log,                           ('1.0: Nicole HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('6847bbbd', 'Nicole.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1dfd9e16', 'Nicole.HairA.LightMap.2048')),
    ],
    'bffb4a66': [
        (log,                           ('1.0: Nicole HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('6847bbbd', 'Nicole.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b8db0209', 'Nicole.HairA.NormalMap.1024')),
    ],
    'b8db0209': [
        (log,                           ('1.0: Nicole HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('6847bbbd', 'Nicole.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bffb4a66', 'Nicole.HairA.NormalMap.2048')),
    ],
    'f86ffe2c': [
        (log,                           ('1.0: Nicole BodyA, BangbooA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9ee9b402', 'Nicole.BodyA.Diffuse.1024')),
    ],
    '9ee9b402': [
        (log,                           ('1.0: Nicole BodyA, BangbooA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f86ffe2c', 'Nicole.BodyA.Diffuse.2048')),
    ],


    '80855e0f': [
        (log,                           ('1.0: Nicole BodyA, BangbooA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('2b5aa784', 'Nicole.BodyA.LightMap.1024')),
    ],
    '2b5aa784': [
        (log,                           ('1.0: Nicole BodyA, BangbooA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('80855e0f', 'Nicole.BodyA.LightMap.2048')),
    ],
    '95cabef3': [
        (log,                           ('1.0: Nicole BodyA, BangbooA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bb33129d', 'Nicole.BodyA.MaterialMap.1024')),
    ],
    'bb33129d': [
        (log,                           ('1.0: Nicole BodyA, BangbooA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('95cabef3', 'Nicole.BodyA.MaterialMap.2048')),
    ],
    '8cf23419': [
        (log,                           ('1.0: Nicole BodyA, BangbooA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('580df52d', 'Nicole.BodyA.NormalMap.1024')),
    ],
    '580df52d': [
        (log,                           ('1.0: Nicole BodyA, BangbooA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('5a4c1ef3', 'Nicole.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8cf23419', 'Nicole.BodyA.NormalMap.2048')),
    ],



    # MARK: Piper
    '940454ef': [(log, ('1.0: Piper Hair IB Hash',)), (add_ib_check_if_missing,)],
    '585da98b': [(log, ('1.0: Piper Body IB Hash',)), (add_ib_check_if_missing,)],
    'e11baad9': [(log, ('1.0: Piper Head IB Hash',)), (add_ib_check_if_missing,)],
    
    
    '4b06ffe6': [(log, ('1.1 -> 1.2: Piper Face Diffuse 1024p Hash',)),   (update_hash, ('f1c8f946',))],
    'f1c8f946': [
        (log,                           ('1.2: Piper HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('e11baad9', 'Piper.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('3b2eb1d9', '97a7862e'), 'Piper.HeadA.Diffuse.2048')),
    ],

    '97a7862e': [(log, ('1.1 -> 1.2: Piper Face Diffuse 2048p Hash',)),   (update_hash, ('3b2eb1d9',))],
    '3b2eb1d9': [
        (log,                           ('1.2: Piper HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('e11baad9', 'Piper.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('f1c8f946', '4b06ffe6'), 'Piper.HeadA.Diffuse.1024')),
    ],

    # Reverted in 1.2
    # '8b6b17f8': [
    #     (log, ('1.0: -> 1.1: Piper Hair Texcoord Hash',)),
    #     (update_hash, ('fd1b9c29',)),
    #     (log, ('+ Remapping texcoord buffer from stride 20 to 32',)),
    #     (update_buffer_element_width, (('BBBB', 'ee', 'ff', 'ee'), ('ffff', 'ee', 'ff', 'ee'), '1.1')),
    #     (log, ('+ Setting texcoord vcolor alpha to 1',)),
    #     (update_buffer_element_value, (('ffff', 'ee', 'ff', 'ee'), ('xxx1', 'xx', 'xx', 'xx'), '1.1'))
    # ],

    'fd1b9c29': [
        (log, ('1.1 -> 1.2: Piper Hair Texcoord Hash',)),
        (update_hash, ('8b6b17f8',)),
        (log, ('+ Remapping texcoord buffer',)),
        (zzz_12_shrink_texcoord_color, ('1.2',))
    ],
    '8b6b17f8': [(log, ('1.3 -> 1.4: Piper Hair Texcoord Hash',)), (update_hash, ('1c6d41af',)),],

    'b2f3e6aa': [(log, ('1.1 -> 1.2: Piper Body Position Hash',)), (update_hash, ('ffe8fea7',)),],
    'a0d146b3': [(log, ('1.1 -> 1.2: Piper Body Texcoord Hash',)), (update_hash, ('a011f94e',)),],
    'a011f94e': [(log, ('1.2 -> 1.3: Piper Body Texcoord Hash',)), (update_hash, ('6357b120',)),],
    '764276de': [(log, ('1.2 -> 1.3: Piper Body Blend Hash',)),    (update_hash, ('3d329807',)),],

    '69ed4d11': [
        (log,                           ('1.0: Piper HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9b743eab', 'Piper.HairA.Diffuse.1024')),
    ],
    '9b743eab': [
        (log,                           ('1.0: Piper HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('69ed4d11', 'Piper.HairA.Diffuse.2048')),
    ],
    '79953d32': [
        (log,                           ('1.0: Piper HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('92acb4d4', 'Piper.HairA.LightMap.1024')),
    ],
    '92acb4d4': [
        (log,                           ('1.0: Piper HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('79953d32', 'Piper.HairA.LightMap.2048')),
    ],
    'b3034dff': [
        (log,                           ('1.0: Piper HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('78c42c66', 'Piper.HairA.MaterialMap.1024')),
    ],
    '78c42c66': [
        (log,                           ('1.0: Piper HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b3034dff', 'Piper.HairA.MaterialMap.2048')),
    ],
    '7ca957d8': [
        (log,                           ('1.0: Piper HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('db7dccbf', 'Piper.HairA.NormalMap.1024')),
    ],
    'db7dccbf': [
        (log,                           ('1.0: Piper HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('940454ef', 'Piper.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7ca957d8', 'Piper.HairA.NormalMap.2048')),
    ],


    '621564e5': [(log, ('1.2 -> 1.3: Piper BodyA Diffuse 1024p Hash',)), (update_hash, ('b450949d',))],
    'b4b74e7e': [(log, ('1.2 -> 1.3: Piper BodyA Diffuse 2048p Hash',)), (update_hash, ('fed40302',))],

    'fed40302': [
        (log,                           ('1.3: Piper BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('b450949d', '621564e5'), 'Piper.BodyA.Diffuse.1024')),
    ],
    'b450949d': [
        (log,                           ('1.3: Piper BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('fed40302', 'b4b74e7e'), 'Piper.BodyA.Diffuse.2048')),
    ],
    '9cc2aaa0': [
        (log,                           ('1.0: Piper BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('db9c7abf', 'Piper.BodyA.LightMap.1024')),
    ],
    'db9c7abf': [
        (log,                           ('1.0: Piper BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9cc2aaa0', 'Piper.BodyA.LightMap.2048')),
    ],
    '7fdee30d': [
        (log,                           ('1.0: Piper BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('73e72a1e', 'Piper.BodyA.MaterialMap.1024')),
    ],
    '73e72a1e': [
        (log,                           ('1.0: Piper BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7fdee30d', 'Piper.BodyA.MaterialMap.2048')),
    ],
    '51f1ec36': [
        (log,                           ('1.0: Piper BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('73a61e88', 'Piper.BodyA.NormalMap.1024')),
    ],
    '73a61e88': [
        (log,                           ('1.0: Piper BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('585da98b', 'Piper.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('51f1ec36', 'Piper.BodyA.NormalMap.2048')),
    ],


    # MARK: Pulchra
    'bd385763': [(log, ('1.6: Pulchra Body IB Hash',)), (add_ib_check_if_missing,)],
    '5b30f4da': [(log, ('1.6: Pulchra Mask IB Hash',)), (add_ib_check_if_missing,)],
    '62de5837': [(log, ('1.6: Pulchra Face IB Hash',)), (add_ib_check_if_missing,)],

    '1626aafe': [
        (log,                           ('1.6: Pulchra FaceA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('62de5837', 'Pulchra.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('32f923f1', 'Pulchra.FaceA.Diffuse.1024')),
    ],
    '32f923f1': [
        (log,                           ('1.6: Pulchra FaceA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('62de5837', 'Pulchra.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1626aafe', 'Pulchra.FaceA.Diffuse.2048')),
    ],

    '7fc03353': [
        (log,                           ('1.6: Pulchra BodyA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('bf7eba0f', 'Pulchra.BodyA.Diffuse.1024')),
    ],
    'd8462af0': [
        (log,                           ('1.6: Pulchra BodyA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('47040200', 'Pulchra.BodyA.LightMap.1024')),
    ],
    'd404b789': [
        (log,                           ('1.6: Pulchra BodyA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('a66a11d0', 'Pulchra.BodyA.MaterialMap.1024')),
    ],
    'bf7eba0f': [
        (log,                           ('1.6: Pulchra BodyA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('7fc03353', 'Pulchra.BodyA.Diffuse.2048')),
    ],
    '47040200': [
        (log,                           ('1.6: Pulchra BodyA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('d8462af0', 'Pulchra.BodyA.LightMap.2048')),
    ],
    'a66a11d0': [
        (log,                           ('1.6: Pulchra BodyA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('d404b789', 'Pulchra.BodyA.MaterialMap.2048')),
    ],

    '57be79d6': [
        (log,                           ('1.6: Pulchra BodyB Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('fb0a816a', 'Pulchra.BodyB.Diffuse.1024')),
    ],
    '12c44063': [
        (log,                           ('1.6: Pulchra BodyB LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('f475e822', 'Pulchra.BodyB.LightMap.1024')),
    ],
    'a553df20': [
        (log,                           ('1.6: Pulchra BodyB MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('64d75415', 'Pulchra.BodyB.MaterialMap.1024')),
    ],
    'fb0a816a': [
        (log,                           ('1.6: Pulchra BodyB Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('57be79d6', 'Pulchra.BodyB.Diffuse.2048')),
    ],
    'f475e822': [
        (log,                           ('1.6: Pulchra BodyB LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('12c44063', 'Pulchra.BodyB.LightMap.2048')),
    ],
    '64d75415': [
        (log,                           ('1.6: Pulchra BodyB MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('a553df20', 'Pulchra.BodyB.MaterialMap.2048')),
    ],

    '46bab365': [
        (log,                           ('1.6: Pulchra Mask Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('128c8f2e', 'Pulchra.Mask.Diffuse.1024')),
    ],
    '03d28ecd': [
        (log,                           ('1.6: Pulchra Mask LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('e522177c', 'Pulchra.Mask.LightMap.1024')),
    ],
    '320a1179': [
        (log,                           ('1.6: Pulchra Mask MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('820ded20', 'Pulchra.Mask.MaterialMap.1024')),
    ],
    '128c8f2e': [
        (log,                           ('1.6: Pulchra Mask Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('46bab365', 'Pulchra.Mask.Diffuse.2048')),
    ],
    'e522177c': [
        (log,                           ('1.6: Pulchra Mask LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('03d28ecd', 'Pulchra.Mask.LightMap.2048')),
    ],
    '820ded20': [
        (log,                           ('1.6: Pulchra Mask MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('320a1179', 'Pulchra.Mask.MaterialMap.2048')),
    ],



    # MARK: Qingyi
    'f6e96452': [(log, ('1.1: Qingyi Head IB Hash',)), (add_ib_check_if_missing,)],
    '3cacba0a': [(log, ('1.1: Qingyi Hair IB Hash',)), (add_ib_check_if_missing,)],
    '195857d8': [(log, ('1.1: Qingyi Body IB Hash',)), (add_ib_check_if_missing,)],

    '0b75cd32': [
        (log,                           ('1.1: Qingyi HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('f6e96452', 'Qingyi.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a58b5444', 'Qingyi.HeadA.Diffuse.1024')),
    ],
    'a58b5444': [
        (log,                           ('1.1: Qingyi HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('f6e96452', 'Qingyi.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0b75cd32', 'Qingyi.HeadA.Diffuse.2048')),
    ],

    '0643440c': [
        (log, ('1.1 -> 1.2: Qingyi Hair Texcoord Hash',)),
        (update_hash, ('53a2b66e',)),
        (log, ('+ Remapping texcoord buffer',)),
        (zzz_12_shrink_texcoord_color, ('1.2',))
    ],

    '3212a0ca': [
        (log,                           ('1.1: Qingyi HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a472db9a', 'Qingyi.HairA.Diffuse.1024')),
    ],
    '2910fbd0': [
        (log,                           ('1.1: Qingyi HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('fc1847a9', 'Qingyi.HairA.NormalMap.1024')),
    ],
    '6e3ac847': [
        (log,                           ('1.1: Qingyi HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('683414c1', 'Qingyi.HairA.LightMap.1024')),
    ],
    '4a77fd3b': [
        (log,                           ('1.1: Qingyi HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bfefa200', 'Qingyi.HairA.MaterialMap.1024')),
    ],
    'a472db9a': [
        (log,                           ('1.1: Qingyi HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3212a0ca', 'Qingyi.HairA.Diffuse.2048')),
    ],
    'fc1847a9': [
        (log,                           ('1.1: Qingyi HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('2910fbd0', 'Qingyi.HairA.NormalMap.2048')),
    ],
    '683414c1': [
        (log,                           ('1.1: Qingyi HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6e3ac847', 'Qingyi.HairA.LightMap.2048')),
    ],
    'bfefa200': [
        (log,                           ('1.1: Qingyi HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('3cacba0a', 'Qingyi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4a77fd3b', 'Qingyi.HairA.MaterialMap.2048')),
    ],
    '1fa7e18e': [
        (log,                           ('1.1: Qingyi BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('aa3c1147', 'Qingyi.BodyA.Diffuse.1024')),
    ],
    '542c6b04': [
        (log,                           ('1.1: Qingyi BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4fbf05be', 'Qingyi.BodyA.NormalMap.1024')),
    ],
    '35c2a022': [
        (log,                           ('1.1: Qingyi BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4a484257', 'Qingyi.BodyA.LightMap.1024')),
    ],
    '41054bb6': [
        (log,                           ('1.1: Qingyi BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4e561ee5', 'Qingyi.BodyA.MaterialMap.1024')),
    ],
    'aa3c1147': [
        (log,                           ('1.1: Qingyi BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1fa7e18e', 'Qingyi.BodyA.Diffuse.2048')),
    ],
    '4fbf05be': [
        (log,                           ('1.1: Qingyi BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('542c6b04', 'Qingyi.BodyA.NormalMap.2048')),
    ],
    '4a484257': [
        (log,                           ('1.1: Qingyi BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('35c2a022', 'Qingyi.BodyA.LightMap.2048')),
    ],
    '4e561ee5': [
        (log,                           ('1.1: Qingyi BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('195857d8', 'Qingyi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('41054bb6', 'Qingyi.BodyA.MaterialMap.2048')),
    ],



    # MARK: Rina
    'cdb2cc7d': [(log, ('1.0: Rina Hair IB Hash',)), (add_ib_check_if_missing,)],
    '2825da1e': [(log, ('1.0: Rina Body IB Hash',)), (add_ib_check_if_missing,)],
    '9f90cfaa': [(log, ('1.0: Rina Head IB Hash',)), (add_ib_check_if_missing,)],


    '7ecc44ce': [
        (log,                           ('1.0: Rina HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('9f90cfaa', 'Rina.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('802a3281', 'Rina.HeadA.Diffuse.2048')),
    ],
    '802a3281': [
        (log,                           ('1.0: Rina HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('9f90cfaa', 'Rina.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7ecc44ce', 'Rina.HeadA.Diffuse.1024')),
    ],


    'eb5d9d1c': [
        (log,                           ('1.0: Rina HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4b005a79', 'Rina.HairA.Diffuse.1024')),
    ],
    '4b005a79': [
        (log,                           ('1.0: Rina HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('eb5d9d1c', 'Rina.HairA.Diffuse.2048')),
    ],
    '1145d2b8': [
        (log,                           ('1.0: Rina HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('fb61499f', 'Rina.HairA.LightMap.1024')),
    ],
    'fb61499f': [
        (log,                           ('1.0: Rina HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1145d2b8', 'Rina.HairA.LightMap.2048')),
    ],
    '82153e28': [
        (log,                           ('1.0: Rina HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ea08fd96', 'Rina.HairA.MaterialMap.1024')),
    ],
    'ea08fd96': [
        (log,                           ('1.0: Rina HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('82153e28', 'Rina.HairA.MaterialMap.2048')),
    ],
    '83ac7993': [
        (log,                           ('1.0: Rina HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('fa3c40e9', 'Rina.HairA.NormalMap.1024')),
    ],
    'fa3c40e9': [
        (log,                           ('1.0: Rina HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('cdb2cc7d', 'Rina.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('83ac7993', 'Rina.HairA.NormalMap.2048')),
    ],


    'bf44bf67': [
        (log,                           ('1.0: Rina BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a23e2e14', 'Rina.BodyA.Diffuse.1024')),
    ],
    'a23e2e14': [
        (log,                           ('1.0: Rina BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('bf44bf67', 'Rina.BodyA.Diffuse.2048')),
    ],
    '95f4e9c8': [
        (log,                           ('1.0: Rina BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('fad76987', 'Rina.BodyA.LightMap.1024')),
    ],
    'fad76987': [
        (log,                           ('1.0: Rina BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('95f4e9c8', 'Rina.BodyA.LightMap.2048')),
    ],
    'ed47722f': [
        (log,                           ('1.0: Rina BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9fa6dfd3', 'Rina.BodyA.MaterialMap.1024')),
    ],
    '9fa6dfd3': [
        (log,                           ('1.0: Rina BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ed47722f', 'Rina.BodyA.MaterialMap.2048')),
    ],
    '97637a8f': [
        (log,                           ('1.0: Rina BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d6b20159', 'Rina.BodyA.NormalMap.1024')),
    ],
    'd6b20159': [
        (log,                           ('1.0: Rina BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('2825da1e', 'Rina.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('97637a8f', 'Rina.BodyA.NormalMap.2048')),
    ],



    # MARK: Seth
    '35cf83ad': [(log, ('1.1: Seth Hair IB Hash',)), (add_ib_check_if_missing,)],
    '00172ec3': [(log, ('1.1: Seth Body IB Hash',)), (add_ib_check_if_missing,)],
    '52f5aa74': [(log, ('1.1: Seth Head IB Hash',)), (add_ib_check_if_missing,)],

    # Reversed in v1.4
    # 'a91eeef2': [
    #     (log,            ('1.2 -> 1.3: Seth Hair Texcoord Hash',)),
    #     (update_hash,    ('a72f760f',)),
    #     (log,            ('+ Remapping texcoord buffer',)),
    #     (zzz_13_remap_texcoord, (
    #         '13_Seth_Hair',
    #         ('4B','2e','2f','2e'),
    #         ('4f','2e','2f','2e')
    #     )),
    # ],
    'a72f760f': [
        (log,            ('1.3 -> 1.4: Seth Hair Texcoord Hash',)),
        (update_hash,    ('a91eeef2',)),
        (log,            ('+ Remapping texcoord buffer',)),
        (zzz_13_remap_texcoord, (
            '14_Seth_Hair',
            ('4f','2e','2f','2e'),
            ('4B','2e','2f','2e')
        )),
    ],

    'fe5b7534': [
        (log,                           ('1.1: Seth HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('52f5aa74', 'Seth.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('09981aff', 'Seth.HeadA.Diffuse.2048')),
    ],
    '09981aff': [
        (log,                           ('1.1: Seth HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('52f5aa74', 'Seth.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('fe5b7534', 'Seth.HeadA.Diffuse.1024')),
    ],

    'dc8e244d': [
        (log,                           ('1.1: Seth HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d3756c37', 'Seth.HairA.Diffuse.1024')),
    ],
    'd3756c37': [
        (log,                           ('1.1: Seth HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('dc8e244d', 'Seth.HairA.Diffuse.2048')),
    ],
    'd4de9ec1': [
        (log,                           ('1.1: Seth HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c01dbf6c', 'Seth.HairA.LightMap.1024')),
    ],
    'c01dbf6c': [
        (log,                           ('1.1: Seth HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d4de9ec1', 'Seth.HairA.LightMap.2048')),
    ],
    '3c256565': [
        (log,                           ('1.1: Seth HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('833e9405', 'Seth.HairA.MaterialMap.1024')),
    ],
    '833e9405': [
        (log,                           ('1.1: Seth HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3c256565', 'Seth.HairA.MaterialMap.2048')),
    ],
    '3376b58c': [
        (log,                           ('1.1: Seth HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('24d52dd8', 'Seth.HairA.NormalMap.1024')),
    ],
    '24d52dd8': [
        (log,                           ('1.1: Seth HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('35cf83ad', 'Seth.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3376b58c', 'Seth.HairA.NormalMap.2048')),
    ],

    '7f8416ab': [
        (log,                           ('1.1: Seth BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('dbc90150', 'Seth.BodyA.Diffuse.1024')),
    ],
    'dbc90150': [
        (log,                           ('1.1: Seth BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7f8416ab', 'Seth.BodyA.Diffuse.2048')),
    ],
    '3d97c2ef': [
        (log,                           ('1.1: Seth BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9436aa83', 'Seth.BodyA.LightMap.1024')),
    ],
    '9436aa83': [
        (log,                           ('1.1: Seth BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3d97c2ef', 'Seth.BodyA.LightMap.2048')),
    ],
    '732d3f81': [
        (log,                           ('1.1: Seth BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('56775fcb', 'Seth.BodyA.MaterialMap.1024')),
    ],
    '56775fcb': [
        (log,                           ('1.1: Seth BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('732d3f81', 'Seth.BodyA.MaterialMap.2048')),
    ],
    'dde45d3d': [
        (log,                           ('1.1: Seth BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('62b047c5', 'Seth.BodyA.NormalMap.1024')),
    ],
    '62b047c5': [
        (log,                           ('1.1: Seth BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('00172ec3', 'Seth.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('dde45d3d', 'Seth.BodyA.NormalMap.2048')),
    ],



    # MARK: Soldier0
    '217ec790': [(log, ('1.6: Soldier0 Hair IB Hash',)), (add_ib_check_if_missing,)],
    '53d3f4e5': [(log, ('1.6: Soldier0 Body IB Hash',)), (add_ib_check_if_missing,)],
    'f2f539b8': [(log, ('1.6: Soldier0 Face IB Hash',)), (add_ib_check_if_missing,)],

    # '05d7b504': [
    #     (log,                           ('1.6: Soldier0 FaceA Diffuse 2048p Hash',)),
    #     (add_section_if_missing,        ('f2f539b8', 'Soldier0.Face.IB', 'match_priority = 0\n')),
    #     (multiply_section_if_missing,   ('692c6d2b', 'Soldier0.FaceA.Diffuse.1024')),
    # ],
    # '692c6d2b': [
    #     (log,                           ('1.6: Soldier0 FaceA Diffuse 1024p Hash',)),
    #     (add_section_if_missing,        ('f2f539b8', 'Soldier0.Face.IB', 'match_priority = 0\n')),
    #     (multiply_section_if_missing,   ('05d7b504', 'Soldier0.FaceA.Diffuse.2048')),
    # ],

    'aa3d57ff': [
        (log,                           ('1.6: Soldier0 Hair Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('8cb4086a', 'Soldier0.Hair.Diffuse.1024')),
    ],
    '8d42a55b': [
        (log,                           ('1.6: Soldier0 Hair LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('96a28554', 'Soldier0.Hair.LightMap.1024')),
    ],
    '464847b3': [
        (log,                           ('1.6: Soldier0 Hair MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('ce3e73be', 'Soldier0.Hair.MaterialMap.1024')),
    ],
    '8cb4086a': [
        (log,                           ('1.6: Soldier0 Hair Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('aa3d57ff', 'Soldier0.Hair.Diffuse.2048')),
    ],
    '96a28554': [
        (log,                           ('1.6: Soldier0 Hair LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('8d42a55b', 'Soldier0.Hair.LightMap.2048')),
    ],
    'ce3e73be': [
        (log,                           ('1.6: Soldier0 Hair MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('464847b3', 'Soldier0.Hair.MaterialMap.2048')),
    ],

    '627baf3f': [
        (log,                           ('1.6: Soldier0 Body Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('0acef326', 'Soldier0.Body.Diffuse.1024')),
    ],
    '3a56b70b': [
        (log,                           ('1.6: Soldier0 Body LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('625ad0eb', 'Soldier0.Body.LightMap.1024')),
    ],
    '7cfa12b6': [
        (log,                           ('1.6: Soldier0 Body MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('dea3c5a0', 'Soldier0.Body.MaterialMap.1024')),
    ],
    '0acef326': [
        (log,                           ('1.6: Soldier0 Body Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('627baf3f', 'Soldier0.Body.Diffuse.2048')),
    ],
    '625ad0eb': [
        (log,                           ('1.6: Soldier0 Body LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('3a56b70b', 'Soldier0.Body.LightMap.2048')),
    ],
    'dea3c5a0': [
        (log,                           ('1.6: Soldier0 Body MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('7cfa12b6', 'Soldier0.Body.MaterialMap.2048')),
    ],



    # MARK: Soldier11
    '2fa74e2f': [(log, ('1.0: Soldier11 Hair IB Hash',)), (add_ib_check_if_missing,)],
    'e3ee72d9': [(log, ('1.0: Soldier11 Body IB Hash',)), (add_ib_check_if_missing,)],
    'bb315c43': [(log, ('1.0: Soldier11 Head IB Hash',)), (add_ib_check_if_missing,)],


    '3c8697e8': [
        (log,                           ('1.0: Soldier11 HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('bb315c43', 'Soldier11.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('67821d9d', 'Soldier11.HeadA.Diffuse.2048')),
    ],
    '67821d9d': [
        (log,                           ('1.0: Soldier11 HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('bb315c43', 'Soldier11.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3c8697e8', 'Soldier11.HeadA.Diffuse.1024')),
    ],


    'b41b671a': [
        (log,                           ('1.0: Soldier11 HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('2fa74e2f', 'Soldier11.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('15f933dc', 'Soldier11.HairA.Diffuse.1024')),
    ],
    '15f933dc': [
        (log,                           ('1.0: Soldier11 HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('2fa74e2f', 'Soldier11.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b41b671a', 'Soldier11.HairA.Diffuse.2048')),
    ],
    '787659b9': [
        (log,                           ('1.0: Soldier11 HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('2fa74e2f', 'Soldier11.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('baa3c836', 'Soldier11.HairA.LightMap.1024')),
    ],
    'baa3c836': [
        (log,                           ('1.0: Soldier11 HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('2fa74e2f', 'Soldier11.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('787659b9', 'Soldier11.HairA.LightMap.2048')),
    ],
    '68d9644a': [
        (log,                           ('1.0: Soldier11 HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('2fa74e2f', 'Soldier11.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4e08e50b', 'Soldier11.HairA.NormalMap.1024')),
    ],
    '4e08e50b': [
        (log,                           ('1.0: Soldier11 HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('2fa74e2f', 'Soldier11.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('68d9644a', 'Soldier11.HairA.NormalMap.2048')),
    ],


    '640a8c01': [
        (log,                           ('1.0: Soldier11 BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d7f2269b', 'Soldier11.BodyA.Diffuse.1024')),
    ],
    'd7f2269b': [
        (log,                           ('1.0: Soldier11 BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('640a8c01', 'Soldier11.BodyA.Diffuse.2048')),
    ],
    '2f88092e': [
        (log,                           ('1.0: Soldier11 BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ce581269', 'Soldier11.BodyA.LightMap.1024')),
    ],
    'ce581269': [
        (log,                           ('1.0: Soldier11 BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('2f88092e', 'Soldier11.BodyA.LightMap.2048')),
    ],
    '81db8cbe': [
        (log,                           ('1.0: Soldier11 BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('874f9f68', 'Soldier11.BodyA.MaterialMap.1024')),
    ],
    '874f9f68': [
        (log,                           ('1.0: Soldier11 BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('81db8cbe', 'Soldier11.BodyA.MaterialMap.2048')),
    ],
    'c94bb3d6': [
        (log,                           ('1.0: Soldier11 BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('eb924a91', 'Soldier11.BodyA.NormalMap.1024')),
    ],
    'eb924a91': [
        (log,                           ('1.0: Soldier11 BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('e3ee72d9', 'Soldier11.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c94bb3d6', 'Soldier11.BodyA.NormalMap.2048')),
    ],



    # MARK: Soukaku
    'fe70c7a3': [(log, ('1.0: Soukaku Hair IB Hash',)), (add_ib_check_if_missing,)],
    'ced49ff8': [(log, ('1.0: Soukaku Body IB Hash',)), (add_ib_check_if_missing,)],
    '1315178e': [(log, ('1.1: Soukaku Mask IB Hash',)), (add_ib_check_if_missing,)],
    '020f9ac6': [(log, ('1.1: Soukaku Head IB Hash',)), (add_ib_check_if_missing,)],

    '01f7369e': [(log, ('1.0 - 1.1: Soukaku Head IB Hash',)), (update_hash, ('020f9ac6',))],


    '2ceacde6': [
        (log,                           ('1.0: Soukaku HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('020f9ac6', '01f7369e'), 'Soukaku.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('427b39a4', 'Soukaku.HeadA.Diffuse.2048')),
    ],
    'c20a8c82': [
        (log,                           ('1.0: Soukaku HeadA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('020f9ac6', '01f7369e'), 'Soukaku.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('17110d01', 'Soukaku.HeadA.Diffuse.2048')),
    ],
    '427b39a4': [
        (log,                           ('1.0: Soukaku HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('020f9ac6', '01f7369e'), 'Soukaku.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('2ceacde6', 'Soukaku.HeadA.Diffuse.1024')),
    ],
    '17110d01': [
        (log,                           ('1.0: Soukaku HeadA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('020f9ac6', '01f7369e'), 'Soukaku.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c20a8c82', 'Soukaku.HeadA.Diffuse.1024')),
    ],


    '32ea0d00': [
        (log,                           ('1.0: Soukaku HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('34a3ff5b', 'Soukaku.HairA.Diffuse.1024')),
    ],
    '34a3ff5b': [
        (log,                           ('1.0: Soukaku HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('32ea0d00', 'Soukaku.HairA.Diffuse.2048')),
    ],
    '04654e94': [
        (log,                           ('1.0: Soukaku HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7bbb3d02', 'Soukaku.HairA.LightMap.1024')),
    ],
    '7bbb3d02': [
        (log,                           ('1.0: Soukaku HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('04654e94', 'Soukaku.HairA.LightMap.2048')),
    ],
    'd1444c52': [
        (log,                           ('1.0: Soukaku HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('218689cf', 'Soukaku.HairA.MaterialMap.1024')),
    ],
    '218689cf': [
        (log,                           ('1.0: Soukaku HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d1444c52', 'Soukaku.HairA.MaterialMap.2048')),
    ],
    '8498ee4d': [
        (log,                           ('1.0: Soukaku HairA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('0003126a', 'Soukaku.HairA.NormalMap.1024')),
    ],
    '0003126a': [
        (log,                           ('1.0: Soukaku HairA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('fe70c7a3', 'Soukaku.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('8498ee4d', 'Soukaku.HairA.NormalMap.2048')),
    ],


    'ee31954b': [
        (log,                           ('1.0: Soukaku BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6f5d31fc', 'Soukaku.BodyA.Diffuse.1024')),
    ],
    '6f5d31fc': [
        (log,                           ('1.0: Soukaku BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ee31954b', 'Soukaku.BodyA.Diffuse.2048')),
    ],
    '112a36a4': [
        (log,                           ('1.0: Soukaku BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c0f0bb74', 'Soukaku.BodyA.LightMap.1024')),
    ],
    'c0f0bb74': [
        (log,                           ('1.0: Soukaku BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('112a36a4', 'Soukaku.BodyA.LightMap.2048')),
    ],
    'd638ddf9': [
        (log,                           ('1.0: Soukaku BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1ec28297', 'Soukaku.BodyA.MaterialMap.1024')),
    ],
    '1ec28297': [
        (log,                           ('1.0: Soukaku BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('d638ddf9', 'Soukaku.BodyA.MaterialMap.2048')),
    ],
    '363e3d70': [
        (log,                           ('1.0: Soukaku BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('77c48d32', 'Soukaku.BodyA.NormalMap.1024')),
    ],
    '77c48d32': [
        (log,                           ('1.0: Soukaku BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('ced49ff8', 'Soukaku.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('363e3d70', 'Soukaku.BodyA.NormalMap.2048')),
    ],



    # MARK: Wise
    'f6cac296': [(log, ('1.0: Wise Hair IB Hash',)), (add_ib_check_if_missing,)],
    'b1df5d22': [(log, ('1.0: Wise Bag IB Hash',)),  (add_ib_check_if_missing,)],
    '8d6acf4e': [(log, ('1.1: Wise Body IB Hash',)), (add_ib_check_if_missing,)],
    '4894246e': [(log, ('1.0: Wise Head IB Hash',)), (add_ib_check_if_missing,)],


    '054ea752': [(log, ('1.0 -> 1.1: Wise Body IB Hash',)),       (update_hash, ('8d6acf4e',))],
    '73c48816': [(log, ('1.0 -> 1.1: Wise Body Draw Hash',)),     (update_hash, ('b581dc0a',))],
    '9581de22': [(log, ('1.0 -> 1.1: Wise Body Position Hash',)), (update_hash, ('67f21c9f',))],
    'a012c752': [(log, ('1.0 -> 1.1: Wise Body Texcoord Hash',)), (update_hash, ('f425bd04',))],

    '67f21c9f': [(log, ('1.2 -> 1.3: Wise Body Position Hash',)), (update_hash, ('f6c5b9f3',))],
    'f425bd04': [(log, ('1.2 -> 1.3: Wise Body Texcoord Hash',)), (update_hash, ('a9d5b70d',))],

    'f6c5b9f3': [(log, ('1.5 -> 1.6: Wise Body Position Hash',)),  (update_hash, ('67f21c9f',))],
    'a9d5b70d': [(log, ('1.5 -> 1.6: Wise Body Texcoord Hash',)),  (update_hash, ('f425bd04',))],

    'cb22cb95': [(log, ('1.2 -> 1.3: Wise Bag Texcoord Hash',)), (update_hash, ('2ae08ae7',))],

    '6c4ae8ce': [(log, ('1.0 -> 1.1: Wise HeadA Diffuse 1024p Hash',)), (update_hash, ('588d7d2d',))],

    '588d7d2d': [
        (log,                           ('1.1: Wise HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('4894246e', 'Wise.Head.IB', 'match_priority = 0\n')),
    ],
    '8f9d78c1': [
        (log,                           ('1.0: Wise HeadA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('4894246e', 'Wise.Head.IB', 'match_priority = 0\n')),
    ],


    '28005a5b': [
        (log,                           ('1.0: Wise HairA, BagA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('cb0d0c22', 'Wise.HairA.Diffuse.1024')),
    ],
    'cb0d0c22': [
        (log,                           ('1.0: Wise HairA, BagA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('28005a5b', 'Wise.HairA.Diffuse.2048')),
    ],
    '1f21c633': [
        (log,                           ('1.0: Wise HairA, BagA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6fcc4ad4', 'Wise.HairA.LightMap.1024')),
    ],
    '6fcc4ad4': [
        (log,                           ('1.0: Wise HairA, BagA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('1f21c633', 'Wise.HairA.LightMap.2048')),
    ],
    '473f816d': [
        (log,                           ('1.0: Wise HairA, BagA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('7c8b0713', 'Wise.HairA.MaterialMap.1024')),
    ],
    '7c8b0713': [
        (log,                           ('1.0: Wise HairA, BagA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('473f816d', 'Wise.HairA.MaterialMap.2048')),
    ],
    '3b4f22ad': [
        (log,                           ('1.0: Wise HairA, BagA NormalMap 2048p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('db08bb73', 'Wise.HairA.NormalMap.1024')),
    ],
    'db08bb73': [
        (log,                           ('1.0: Wise HairA, BagA NormalMap 1024p Hash',)),
        (add_section_if_missing,        ('f6cac296', 'Wise.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('3b4f22ad', 'Wise.HairA.NormalMap.2048')),
    ],


    '84529dab': [(log, ('1.0 - 1.1: Wise BodyA Diffuse 2048p Hash',)), (update_hash, ('868709f2',))],
    '868709f2': [
        (log,                           ('1.1: Wise BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('3d7a53b0', 'ef76b675'), 'Wise.BodyA.Diffuse.1024')),
    ],

    'ef76b675': [(log, ('1.0 - 1.1: Wise BodyA Diffuse 1024p Hash',)), (update_hash, ('3d7a53b0',))],
    '3d7a53b0': [
        (log,                           ('1.1: Wise BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('868709f2', '84529dab'), 'Wise.BodyA.Diffuse.2048')),
    ],
    '088718a9': [
        (log,                           ('1.0: Wise BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('9f46182a', 'Wise.BodyA.LightMap.1024')),
    ],
    '9f46182a': [
        (log,                           ('1.0: Wise BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('088718a9', 'Wise.BodyA.LightMap.2048')),
    ],
    'a5fdb5e7': [
        (log,                           ('1.0: Wise BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('148283b7', 'Wise.BodyA.MaterialMap.1024')),
    ],
    '148283b7': [
        (log,                           ('1.0: Wise BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a5fdb5e7', 'Wise.BodyA.MaterialMap.2048')),
    ],
    'f43c8025': [
        (log,                           ('1.0: Wise BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('6807521d', 'Wise.BodyA.NormalMap.1024')),
    ],
    '6807521d': [
        (log,                           ('1.0: Wise BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('8d6acf4e', '054ea752'), 'Wise.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f43c8025', 'Wise.BodyA.NormalMap.2048')),
    ],



    # MARK: Yanagi
    '9e12899f': [(log, ('1.3: Yanagi Hair IB Hash',)),    (add_ib_check_if_missing,)],
    'f478ee4c': [(log, ('1.3: Yanagi Body IB Hash',)),    (add_ib_check_if_missing,)],
    # '27d49f0b': [(log, ('1.3: Yanagi Sheathe IB Hash',)), (add_ib_check_if_missing,)],
    # '2d7f2223': [(log, ('1.3: Yanagi Weapon IB Hash',)),  (add_ib_check_if_missing,)],
    '0817204c': [(log, ('1.3: Yanagi Face IB Hash',)),    (add_ib_check_if_missing,)],


    'cfe7ab46': [
        (log,                           ('1.3: Yanagi FaceA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('0817204c', 'Yanagi.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('95d9e92e', 'Yanagi.FaceA.Diffuse.2048')),
    ],
    '95d9e92e': [
        (log,                           ('1.3: Yanagi FaceA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('0817204c', 'Yanagi.Face.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('cfe7ab46', 'Yanagi.FaceA.Diffuse.1024')),
    ],

    '4edb5c79': [
        (log,                           ('1.3: Yanagi HairA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('9e12899f', 'Yanagi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('ac5f6d76', 'Yanagi.HairA.Diffuse.2048')),
    ],
    '5a43d985': [
        (log,                           ('1.3: Yanagi HairA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('9e12899f', 'Yanagi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('99cfa935', 'Yanagi.HairA.LightMap.2048')),
    ],
    '486e3c42': [
        (log,                           ('1.3: Yanagi HairA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('9e12899f', 'Yanagi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f80b57f0', 'Yanagi.HairA.MaterialMap.2048')),
    ],
    'ac5f6d76': [
        (log,                           ('1.3: Yanagi HairA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('9e12899f', 'Yanagi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('4edb5c79', 'Yanagi.HairA.Diffuse.1024')),
    ],
    '99cfa935': [
        (log,                           ('1.3: Yanagi HairA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('9e12899f', 'Yanagi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('5a43d985', 'Yanagi.HairA.LightMap.1024')),
    ],
    'f80b57f0': [
        (log,                           ('1.3: Yanagi HairA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('9e12899f', 'Yanagi.Hair.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('486e3c42', 'Yanagi.HairA.MaterialMap.1024')),
    ],


    'c119dbd7': [
        (log,                           ('1.3: Yanagi BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('f478ee4c', 'Yanagi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c7c4f5c5', 'Yanagi.BodyA.Diffuse.2048')),
    ],
    'f60602ec': [
        (log,                           ('1.3: Yanagi BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        ('f478ee4c', 'Yanagi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('08933e28', 'Yanagi.BodyA.LightMap.2048')),
    ],
    'b29f0188': [
        (log,                           ('1.3: Yanagi BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        ('f478ee4c', 'Yanagi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c2ae5d2b', 'Yanagi.BodyA.MaterialMap.2048')),
    ],
    'c7c4f5c5': [
        (log,                           ('1.3: Yanagi BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('f478ee4c', 'Yanagi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('c119dbd7', 'Yanagi.BodyA.Diffuse.1024')),
    ],
    '08933e28': [
        (log,                           ('1.3: Yanagi BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        ('f478ee4c', 'Yanagi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('f60602ec', 'Yanagi.BodyA.LightMap.1024')),
    ],
    'c2ae5d2b': [
        (log,                           ('1.3: Yanagi BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        ('f478ee4c', 'Yanagi.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('b29f0188', 'Yanagi.BodyA.MaterialMap.1024')),
    ],


    # 'aaccff06': [
    #     (log,                           ('1.3: Yanagi WeaponA, SheatheA Diffuse 1024p Hash',)),
    #     (add_section_if_missing,        ('2d7f2223', 'Yanagi.Weapon.IB', 'match_priority = 0\n')),
    #     (add_section_if_missing,        ('27d49f0b', 'Yanagi.Sheathe.IB', 'match_priority = 0\n')),
    #     # (multiply_section_if_missing,   ('a1eabb9f', 'Yanagi.WeaponA.Diffuse.2048')),
    # ],
    # '8ef68839': [
    #     (log,                           ('1.3: Yanagi WeaponA, SheatheA LightMap 1024p Hash',)),
    #     (add_section_if_missing,        ('2d7f2223', 'Yanagi.Weapon.IB', 'match_priority = 0\n')),
    #     (add_section_if_missing,        ('27d49f0b', 'Yanagi.Sheathe.IB', 'match_priority = 0\n')),
    #     # (multiply_section_if_missing,   ('a1eabb9f', 'Yanagi.WeaponA.LightMap.2048')),
    # ],
    # 'ecd8605e': [
    #     (log,                           ('1.3: Yanagi WeaponA, SheatheA MaterialMap 1024p Hash',)),
    #     (add_section_if_missing,        ('2d7f2223', 'Yanagi.Weapon.IB', 'match_priority = 0\n')),
    #     (add_section_if_missing,        ('27d49f0b', 'Yanagi.Sheathe.IB', 'match_priority = 0\n')),
    #     # (multiply_section_if_missing,   ('a1eabb9f', 'Yanagi.WeaponA.MaterialMap.2048')),
    # ],



    # MARK: ZhuYuan
    '6619364f': [(log, ('1.1: ZhuYuan Body IB Hash',)),         (add_ib_check_if_missing,)],
    '9821017e': [(log, ('1.0: ZhuYuan Hair IB Hash',)),         (add_ib_check_if_missing,)],
    'fcac8411': [(log, ('1.0: ZhuYuan Extras IB Hash',)),       (add_ib_check_if_missing,)],
    '5e717358': [(log, ('1.0: ZhuYuan ShoulderAmmo IB Hash',)), (add_ib_check_if_missing,)],
    'a63028ae': [(log, ('1.0: ZhuYuan HipAmmo IB Hash',)),      (add_ib_check_if_missing,)],
    'f1c241b7': [(log, ('1.0: ZhuYuan Head IB Hash',)),         (add_ib_check_if_missing,)],
    
    'a4aeb1d5': [(log, ('1.0 -> 1.1: ZhuYuan Body IB Hash',)),  (update_hash, ('6619364f',))],


    'f3569f8d': [(log, ('1.0 -> 1.1: ZhuYuan Body Position Hash',)), (update_hash, ('f595d24d',))],
    '160872c0': [(log, ('1.0 -> 1.1: ZhuYuan Body Texcoord Hash',)), (update_hash, ('cb885260',))],


    # Reverted in 1.2
    # Comment out to prevent infinite loop :/
    # 'f3c092c5': [
    #     (log, ('1.0 -> 1.1: ZhuYuan Hair Texcoord Hash',)),
    #     (update_hash, ('fdc045fc',)),
    #     (log, ('+ Remapping texcoord buffer from stride 20 to 32',)),
    #     (update_buffer_element_width, (('BBBB', 'ee', 'ff', 'ee'), ('ffff', 'ee', 'ff', 'ee'), '1.1')),
    #     (log, ('+ Setting texcoord vcolor alpha to 1',)),
    #     (update_buffer_element_value, (('ffff', 'ee', 'ff', 'ee'), ('xxx1', 'xx', 'xx', 'xx'), '1.1'))
    # ],

    'fdc045fc': [
        (log, ('1.1 -> 1.2: ZhuYuan Hair Texcoord Hash',)),
        (update_hash, ('f3c092c5',)),
        (log, ('+ Reverting texcoord buffer remap',)),
        (zzz_12_shrink_texcoord_color, ('1.2',))
    ],

    '138c7d76': [
        (log,                           ('1.0: ZhuYuan HeadA Diffuse 1024p Hash',)),
        (add_section_if_missing,        ('f1c241b7', 'ZhuYuan.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('a1eabb9f', 'ZhuYuan.HeadA.Diffuse.2048')),
    ],
    'a1eabb9f': [
        (log,                           ('1.0: ZhuYuan HeadA Diffuse 2048p Hash',)),
        (add_section_if_missing,        ('f1c241b7', 'ZhuYuan.Head.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   ('138c7d76', 'ZhuYuan.HeadA.Diffuse.1024')),
    ],


    '9b86c2f6': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('7f823598', 'ZhuYuan.HairA.Diffuse.2048')),
    ],
    '6eb346b9': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('4ac1defe', 'ZhuYuan.HairA.NormalMap.2048')),
    ],
    '8955095f': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('d4ee59c7', 'ZhuYuan.HairA.LightMap.2048')),
    ],
    '7d884663': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('12a407b1', 'ZhuYuan.HairA.MaterialMap.2048')),
    ],

    '7f823598': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('9b86c2f6', 'ZhuYuan.HairA.Diffuse.1024')),
    ],
    '4ac1defe': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('6eb346b9', 'ZhuYuan.HairA.NormalMap.1024')),
    ],
    'd4ee59c7': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('8955095f', 'ZhuYuan.HairA.LightMap.1024')),
    ],
    '12a407b1': [
        (log,                           ('1.0: ZhuYuan HairA, ExtrasA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('7d884663', 'ZhuYuan.HairA.MaterialMap.1024')),
    ],


    'b57a8744': [(log, ('1.0 -> 1.1: ZhuYuan BodyA Diffuse 1024p Hash',)),     (update_hash, ('f6795718',))],
    '833bafd5': [(log, ('1.0 -> 1.1: ZhuYuan BodyA NormalMap 1024p Hash',)),   (update_hash, ('729ea75a',))],
    '18d00ac6': [(log, ('1.0 -> 1.1: ZhuYuan BodyA LightMap 1024p Hash',)),    (update_hash, ('14b638b6',))],
    '1daa379f': [(log, ('1.0 -> 1.1: ZhuYuan BodyA MaterialMap 1024p Hash',)), (update_hash, ('cd4dee2c',))],

    'f6795718': [(log, ('1.1 -> 1.2: ZhuYuan BodyA Diffuse 1024p Hash',)),     (update_hash, ('46af14f8',))],
    '729ea75a': [(log, ('1.1 -> 1.2: ZhuYuan BodyA NormalMap 1024p Hash',)),   (update_hash, ('d5b175bf',))],
    '14b638b6': [(log, ('1.1 -> 1.2: ZhuYuan BodyA LightMap 1024p Hash',)),    (update_hash, ('fb385169',))],
    'cd4dee2c': [(log, ('1.1 -> 1.2: ZhuYuan BodyA MaterialMap 1024p Hash',)), (update_hash, ('29e2ebc5',))],

    '46af14f8': [
        (log,                           ('1.2: ZhuYuan BodyA Diffuse 1024p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('a271e894', '3ef82f41', 'c88e7660'), 'ZhuYuan.BodyA.Diffuse.2048')),
    ],
    'd5b175bf': [
        (log,                           ('1.2: ZhuYuan BodyA NormalMap 1024p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('d81fb56e', '7195a311', 'a396c53a'), 'ZhuYuan.BodyA.NormalMap.2048')),
    ],
    'fb385169': [
        (log,                           ('1.2: ZhuYuan BodyA LightMap 1024p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('d02bc66c', '80ebf536', '13a38449'), 'ZhuYuan.BodyA.LightMap.2048')),
    ],
    '29e2ebc5': [
        (log,                           ('1.2: ZhuYuan BodyA MaterialMap 1024p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('3e808ef6', '10415de8', 'b4e20235'), 'ZhuYuan.BodyA.MaterialMap.2048')),
    ],

    'c88e7660': [(log, ('1.0 -> 1.1: ZhuYuan BodyA Diffuse 2048p Hash',)),     (update_hash, ('3ef82f41',))],
    'a396c53a': [(log, ('1.0 -> 1.1: ZhuYuan BodyA NormalMap 2048p Hash',)),   (update_hash, ('7195a311',))],
    '13a38449': [(log, ('1.0 -> 1.1: ZhuYuan BodyA LightMap 2048p Hash',)),    (update_hash, ('80ebf536',))],
    'b4e20235': [(log, ('1.0 -> 1.1: ZhuYuan BodyA MaterialMap 2048p Hash',)), (update_hash, ('10415de8',))],

    '3ef82f41': [(log, ('1.0 -> 1.1: ZhuYuan BodyA Diffuse 2048p Hash',)),     (update_hash, ('a271e894',))],
    '7195a311': [(log, ('1.0 -> 1.1: ZhuYuan BodyA NormalMap 2048p Hash',)),   (update_hash, ('d81fb56e',))],
    '80ebf536': [(log, ('1.0 -> 1.1: ZhuYuan BodyA LightMap 2048p Hash',)),    (update_hash, ('d02bc66c',))],
    '10415de8': [(log, ('1.0 -> 1.1: ZhuYuan BodyA MaterialMap 2048p Hash',)), (update_hash, ('3e808ef6',))],

    'a271e894': [
        (log,                           ('1.1: ZhuYuan BodyA Diffuse 2048p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('46af14f8', 'f6795718', 'b57a8744'), 'ZhuYuan.BodyA.Diffuse.1024')),
    ],
    'd81fb56e': [
        (log,                           ('1.1: ZhuYuan BodyA NormalMap 2048p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('d5b175bf', '729ea75a', '833bafd5'), 'ZhuYuan.BodyA.NormalMap.1024')),
    ],
    'd02bc66c': [
        (log,                           ('1.1: ZhuYuan BodyA LightMap 2048p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('fb385169', '14b638b6', '18d00ac6'), 'ZhuYuan.BodyA.LightMap.1024')),
    ],
    '3e808ef6': [
        (log,                           ('1.1: ZhuYuan BodyA MaterialMap 2048p Hash',)),
        (add_section_if_missing,        (('a4aeb1d5', '6619364f'), 'ZhuYuan.Body.IB', 'match_priority = 0\n')),
        (multiply_section_if_missing,   (('29e2ebc5', 'cd4dee2c', '1daa379f'), 'ZhuYuan.BodyA.MaterialMap.1024')),
    ],


    '222ae5ee': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA Diffuse 1024p Hash',)),
        (multiply_section_if_missing,   ('6a33b25e', 'ZhuYuan.ExtrasB.Diffuse.2048')),
    ],
    '0fda74c3': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA NormalMap 1024p Hash',)),
        (multiply_section_if_missing,   ('fb35b7e9', 'ZhuYuan.ExtrasB.NormalMap.2048')),
    ],
    '790183b4': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA LightMap 1024p Hash',)),
        (multiply_section_if_missing,   ('e30f025b', 'ZhuYuan.ExtrasB.LightMap.2048')),
    ],
    '84842409': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA MaterialMap 1024p Hash',)),
        (multiply_section_if_missing,   ('58d5c840', 'ZhuYuan.ExtrasB.MaterialMap.2048')),
    ],

    '6a33b25e': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA Diffuse 2048p Hash',)),
        (multiply_section_if_missing,   ('222ae5ee', 'ZhuYuan.ExtrasB.Diffuse.1024')),
    ],
    'fb35b7e9': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA NormalMap 2048p Hash',)),
        (multiply_section_if_missing,   ('0fda74c3', 'ZhuYuan.ExtrasB.NormalMap.1024')),
    ],
    'e30f025b': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA LightMap 2048p Hash',)),
        (multiply_section_if_missing,   ('790183b4', 'ZhuYuan.ExtrasB.LightMap.1024')),
    ],
    '58d5c840': [
        (log,                           ('1.0: ZhuYuan ExtrasB, ShoulderAmmoA, HipAmmoA MaterialMap 2048p Hash',)),
        (multiply_section_if_missing,   ('84842409', 'ZhuYuan.ExtrasB.MaterialMap.1024')),
    ],



}


# MARK: Regex
# Using VERBOSE flag to ignore whitespace
# https://docs.python.org/3/library/re.html#re.VERBOSE
def get_section_hash_pattern(hash) -> re.Pattern:
    return re.compile(
        r'''
            ^(
                [ \t]*?\[(?:Texture|Shader)Override.*\][ \t]*
                (?:\n
                    (?![ \t]*?(?:\[|hash\s*=))
                    .*$
                )*?
                (?:\n\s*hash\s*=\s*{}[ \t]*)
                (?:
                    (?:\n(?![ \t]*?\[).*$)*
                    (?:\n[\t ]*?[\$\w].*$)
                )?
            )\s*
        '''.format(hash),
        flags=re.VERBOSE|re.IGNORECASE|re.MULTILINE
    )


def get_section_title_pattern(title) -> re.Pattern:
    return re.compile(
        r'''
            ^(
                [ \t]*?\[{}\]
                (?:
                    (?:\n(?![ \t]*?\[).*$)*
                    (?:\n[\t ]*?[\$\w].*$)
                )?
            )\s*
        '''.format(title),
        flags=re.VERBOSE|re.IGNORECASE|re.MULTILINE
    )



# MARK: RUN
if __name__ == '__main__':
    try: main()
    except Exception as x:
        print('\nError Occurred: {}\n'.format(x))
        print(traceback.format_exc())
    finally:
        input('\nPress "Enter" to quit...\n')
