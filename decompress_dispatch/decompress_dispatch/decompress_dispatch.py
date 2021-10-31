from typing import Optional
from stoq.data_classes import Payload, DispatcherResponse, Request, PayloadMeta, ExtractedPayload
from stoq.helpers import StoqConfigParser
from stoq.plugins import DispatcherPlugin
from stoq.exceptions import StoqPluginException

import magic

"""
Overview
=======
route an event based on its mime type. This hack-copies parts of decompress and parts of mimetype, to allow it
to make decisions based on the mime type of the file.

"""
# copied from the decompress plugin. If that changes to support more stuff, need to update this also.
# note: handle dosexec a little differently since those could be a regular executable *or* a upx-packed one.
# in that case, send it *both* ways.
SUPPORTED_ARCHIVE_TYPES = {
        'application/gzip',
        'application/jar',
        'application/java-archive',
        'application/rar',
        'application/x-7z-compressed',
        'application/x-lzma',
        'application/x-ace',
        'application/x-gzip',
        'application/x-rar',
        'application/x-tar',
        'application/x-zip-compressed',
        'application/zip',
        'application/x-bzip2',
        'application/octet-stream',
        'application/vnd.debian.binary-package',
        'application/vnd.ms-cab-compressed',
        'application/x-arj',
        'application/x-lha',
        'application/x-lzma',
        'application/x-rpm',
        'application/x-xz',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.openxmlformats-officedocument.presentationml.template',
        'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
    }

DOUBLE_TYPES = {'application/x-dosexec'}

if hasattr(magic.Magic, 'from_buffer'):
    USE_PYTHON_MAGIC = True
else:
    USE_PYTHON_MAGIC = False


class DecompressDispatcherPlugin(DispatcherPlugin):
    def __init__(self, config: StoqConfigParser):
        super().__init__(config)
        self.always_dispatch = config.getlist('options', 'always_dispatch', fallback=[])

    @staticmethod
    def get_mimetype(payload):
        if USE_PYTHON_MAGIC:
            magic_scan = magic.Magic(mime=True)
            magic_result = magic_scan.from_buffer(payload.content[0:1000])
        else:
            with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
                magic_result = m.id_buffer(payload.content[0:1000])
        if hasattr(magic_result, 'decode'):
            magic_result = magic_result.decode('utf-8')
        return magic_result

    async def get_dispatches(
        self, payload: Payload, request: Request
    ) -> Optional[DispatcherResponse]:
        response = DispatcherResponse()
        mimetype = self.get_mimetype(payload)
        if mimetype in SUPPORTED_ARCHIVE_TYPES:
            response.plugin_names.append("decompress")
            response.meta = {"dispatch_status": "archive file, sending to decompress only"}
        elif mimetype in DOUBLE_TYPES:
            response.plugin_names.extend(self.always_dispatch)
            response.plugin_names.append("decompress")
            response.meta = {"dispatch_status": "possible dual-type file. Sending to plugins and decompress"}
        else:
            response.plugin_names.extend(self.always_dispatch)
            response.meta = {"dispatch_status": "not archive file, sending to analysis"}
        return response
