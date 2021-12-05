"""
Overview
========
Parse and abstract PE, ELF and MachO files using LIEF in EMBER format
"""

import lief

from stoq.helpers import StoqConfigParser
from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq import Payload, Request, WorkerResponse


class LiefPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.abstract = config.getboolean('options', 'abstract', fallback=True)

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Scan a payload using LIEF, return it with the EMBER-formatted info
        """
        filename = payload.results.payload_meta.extra_data.get(
            'filename', payload.results.payload_id
        )

        try:
            lief_obj = lief.parse(raw=list(payload.content), name=filename)
        except lief.exception as err:
            raise StoqPluginException(f'Unable to parse payload: {err}')

        if lief_obj is None:
            raise StoqPluginException('The file type isn\'t supported by LIEF')

        lief_info = {
            'size': len(payload.content),
            'vsize': lief_obj.virtual_size,
            'has_debug': int(getattr(lief_obj, "has_debug", 0)),
            'exports': len(lief_obj.exported_functions),
            'imports': len(lief_obj.imported_functions),
            'has_relocations': int(getattr(lief_obj, "has_relocations", 0)),
            'has_resources': int(getattr(lief_obj, "has_resources", 0)),
            'has_signature': int(getattr(lief_obj, "has_signature", 0)),
            'has_tls': int(getattr(lief_obj, "has_tls", 0)),
            'symbols': len(lief_obj.symbols),
            'coff': {
                'timestamp': getattr(lief_obj.header, "time_date_stamps", ""),
                'machine': str(lief_obj.header.machine).split('.')[-1],
                'characteristics': [str(c).split('.')[-1] for c in lief_obj.header.characteristics_list]
            },
        }
        if hasattr(lief_obj, "optional_header"):
            lief_info["optional"] = {
                'subsystem': str(getattr(lief_obj.optional_header, "subsystem", "")).split('.')[-1],
                'dll_characteristics': [
                    str(c).split('.')[-1] for c in getattr(lief_obj.optional_header, "dll_characteristics_lists", [])
                ],
                'magic': str(getattr(lief_obj.optional_header, "magic", "")).split('.')[-1],
                'major_image_version': getattr(lief_obj.optional_header, "major_image_version", ""),
                'minor_image_version': getattr(lief_obj.optional_header, "minor_image_version", ""),
                'major_linker_version': getattr(lief_obj.optional_header, "major_linker_version", ""),
                'minor_linker_version': getattr(lief_obj.optional_header, "minor_linker_version", ""),
                'major_operating_system_version': getattr(lief_obj.optional_header, "major_operating_system_version"),
                'minor_operating_system_version': getattr(lief_obj.optional_header, "minor_operating_system_version"),
                'major_subsystem_version': getattr(lief_obj.optional_header, "major_subsystem_version"),
                'minor_subsystem_version': getattr(lief_obj.optional_header, "minor_subsystem_version"),
                'sizeof_code': getattr(lief_obj.optional_header, "sizeof_code"),
                'sizeof_headers': getattr(lief_obj.optional_header, "sizeof_headers", ""),
                'sizeof_heap_commit': getattr(lief_obj.optional_header, "sizeof_heap_commit", "")
            }

        return WorkerResponse(lief_info)
