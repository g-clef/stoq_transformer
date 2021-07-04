from typing import Optional
from stoq.data_classes import Payload, DispatcherResponse, Request
from stoq.helpers import StoqConfigParser
from stoq.plugins import DispatcherPlugin

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


class DecompressDispatcherPlugin(DispatcherPlugin):
    def __init__(self, config: StoqConfigParser):
        super().__init__(config)
        self.always_dispatch = config.getlist('options', 'always_dispatch', fallback=[])

    async def get_dispatches(
        self, payload: Payload, request: Request
    ) -> Optional[DispatcherResponse]:
        response = DispatcherResponse()
        mimetype = payload.results.workers['mimetype']['mimetype']
        if mimetype in SUPPORTED_ARCHIVE_TYPES:
            response.plugin_names = ['decompress']
        elif mimetype in DOUBLE_TYPES:
            response.plugin_names = self.always_dispatch + ["decompress"]
        else:
            response.plugin_names = self.always_dispatch
        return response