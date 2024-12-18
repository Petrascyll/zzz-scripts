import re
import struct
import traceback
from pathlib import Path

'''
    ZZZ Ellen Hair v1.4A Blend Remap
    Place this script in the SAME FOLDER as the Ellen mod that requires a blend remap and run it.
    Do NOT run this remap script on Ellen mods that dont require a blend remap.
    Do NOT run this remap script on the same Ellen mod more than once.

    Written by Petrascyll.
    Thanks to Hazel for help finding old/new vgx changes and SilentNightSound for suggesting safeguard.
'''


POSITION_HASH = 'ba0fe600'
OLD_VGX = [34, 35, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 49, 50]
NEW_VGX = [39, 34, 40, 35, 38, 42, 43, 44, 45, 46, 47, 41, 50, 49]


def process_folder(folder_path: Path) -> list[Path]:
    ini_filepaths: list[Path] = []
    for path in folder_path.iterdir():
        if path.name.upper().startswith('DISABLED') and path.name.lower().endswith('.ini'):
            continue
        if path.name.upper().startswith('DESKTOP'):
            continue

        if path.is_dir():
            ini_filepaths.extend(process_folder(path))
        elif path.name.endswith('.ini'):
            ini_filepaths.append(path)

    return ini_filepaths

def get_blend_filepaths(ini_filepath: Path) -> list[Path]:
    ini_content = ini_filepath.read_text(encoding='utf-8')
    
    pattern = get_section_hash_pattern(POSITION_HASH)
    position_override_match = pattern.search(ini_content)
    if not position_override_match: return []
    blend_resources = get_blend_resources(ini_content, position_override_match.group(1))

    blend_filepaths: list[Path] = []
    line_pattern = re.compile(r'^\s*filename\s*=\s*(.*)\s*$', flags=re.IGNORECASE)
    for blend_resource in blend_resources:
            pattern = get_section_title_pattern(blend_resource)
            resource_section_match = pattern.search(ini_content)
            if not resource_section_match: continue

            for line in resource_section_match.group(1).splitlines():
                if line_match := line_pattern.match(line):
                    blend_filepaths.append(ini_filepath.parent / line_match.group(1))
                    break

    return blend_filepaths


def get_blend_resources(ini_content: str, commandlist: str):
    line_pattern = re.compile(r'^\s*(run|vb2)\s*=\s*(.*)\s*$', flags=re.IGNORECASE)
    resources = []

    for line in commandlist.splitlines():
        line_match = line_pattern.match(line)
        if not line_match: continue

        if line_match.group(1) == 'vb2':
            resources.append(line_match.group(2))

        elif line_match.group(1) == 'run':
            commandlist_title = line_match.group(2)
            pattern = get_section_title_pattern(commandlist_title)
            commandlist_match = pattern.search(ini_content)
            if commandlist_match:
                sub_resources = get_blend_resources(ini_content, commandlist_match.group(1))
                resources.extend(sub_resources)

    return resources

def get_blend_remap(buffer: bytes):
    new_buffer = bytearray()
    
    blend_stride = 32
    vertex_count = len(buffer)//blend_stride
    for i in range(vertex_count):
        blend_weights  = struct.unpack_from('<4f', buffer, i*blend_stride + 0)
        blend_indices  = struct.unpack_from('<4I', buffer, i*blend_stride + 16)

        new_buffer.extend(struct.pack('<4f4I', *blend_weights, *[
            vgx if vgx not in OLD_VGX
            else NEW_VGX[OLD_VGX.index(vgx)]
            for vgx in blend_indices
        ]))
    
    return new_buffer

def get_section_hash_pattern(hash) -> re.Pattern:
    return re.compile(r'^([ \t]*?\[(?:Texture|Shader)Override.*\][ \t]*(?:\n(?![ \t]*?\[).*?$)*?(?:\n\s*hash\s*=\s*{}[ \t]*)(?:(?:\n(?![ \t]*?\[).*?$)*(?:\n[\t ]*?[\$\w].*?$))?)\s*'.format(hash), flags=re.VERBOSE|re.IGNORECASE|re.MULTILINE)
def get_section_title_pattern(title) -> re.Pattern:
    return re.compile(r'^([ \t]*?\[{}\](?:(?:\n(?![ \t]*?\[).*?$)*(?:\n[\t ]*?[\$\w].*?$))?)\s*'.format(title), flags=re.VERBOSE|re.IGNORECASE|re.MULTILINE)

def get_backup_filepath(blend_filepath: Path):
    return (blend_filepath.parent / f'{blend_filepath.name[:-4]}.14A_BACKUP.buf')
def get_marker_filepath(blend_filepath: Path):
    return (blend_filepath.parent / f'{blend_filepath.name[:-4]}.14A_REMAP_APPLIED.empty')


def main():
    print('CWD: {}'.format(Path('.').absolute()))
    print('ELLEN 1.4A HAIR REMAP')
    print()

    blend_filepaths: list[Path] = []
    for ini_filepath in process_folder(Path('.')):
        try:
            blend_filepaths.extend(get_blend_filepaths(ini_filepath))
        except:
            traceback.print_exc()
            print(f'\nFailed to parse "{ini_filepath}". Aborting')
            return
    blend_filepaths = sorted(set(blend_filepaths))

    if len(blend_filepaths) == 0:
        print('Didn\'t find any matching blend buffers to remap. Exiting.')
        return

    print('Found blend files to remap:')
    blend_data: list[tuple[Path, bytes, bytearray]] = []
    for blend_filepath in blend_filepaths:
        print(f'- "{blend_filepath.absolute()}"')

        backup_filepath = get_backup_filepath(blend_filepath)
        marker_filepath = get_marker_filepath(blend_filepath)
        if backup_filepath.exists() or marker_filepath.exists():
            print('  14A Blend remap has already been applied to the above file!!! You MUST not run this remap script on the same Ellen mod more than once!! Aborting')
            return

        blend_buffer = blend_filepath.read_bytes()
        blend_remap  = get_blend_remap(blend_buffer)
        blend_data.append((blend_filepath, blend_buffer, blend_remap))

    print()
    print('Do NOT run this remap script on Ellen mods that dont require a blend remap!!!')
    print('Do NOT run this remap script on the same Ellen mod more than once!!!')
    print('Type \'Sucrose\' and press Enter to apply the blend remap to the above files.')
    print('YOU HAVE BEEN WARNED.')
    
    user_input = input()
    if user_input.lower() != 'sucrose':
        print(f'User entered \'{user_input}\'. Aborting!')
        return

    print('Applying blend remap... ', end='')
    for blend_filepath, blend_buffer, blend_remap in blend_data:
        backup_filepath = get_backup_filepath(blend_filepath)
        marker_filepath = get_marker_filepath(blend_filepath)
        
        backup_filepath.write_bytes(blend_buffer)
        blend_filepath .write_bytes(blend_remap)
        marker_filepath.write_text('', encoding='utf-8')
    print('Done')


if __name__ == '__main__':
    try: main()
    except Exception as x:
        print('\nError Occurred: {}\n'.format(x))
        print(traceback.format_exc())
    finally:
        input()
