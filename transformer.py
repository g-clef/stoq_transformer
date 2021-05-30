import asyncio
import json
import os

from stoq import Stoq, RequestMeta


def make_stoq(input_path):
    es_username = os.environ.get("ES_USERNAME", "es")
    es_password = os.environ.get("ES_PASSWORD", "password")
    es_host = os.environ.get("ES_HOST", "es")
    es_index = os.environ.get("ES_INDEX", "malwarETL")
    stoq_home = os.environ.get("STOQ_HOME", "/app")
    plugin_home = os.path.join(stoq_home, "plugins")
    providers = ["dirmon"]
    workers = ["decompress"]
    always_dispatch = ",".join(["EMBER_format_lief",
                                "entropy",
                                "hash",
                                "hash_ssdeep",
                                "lief",
                                "mimetype",
                                "mraptor",
                                "ole",
                                "peinfo",
                                "rtf",
                                "symhash",
                                "xdpcarve",
                                "xyz"]
                               )
    # connectors = ['es-search']
    connectors = ['stdout']
    plugin_opts = {"dirmon": {"source_dir": input_path},
                   "decompress": {'passwords': "infected",
                                  "always_dispatch": always_dispatch},
                   "es-search": {"es_options": json.dumps({"http_auth": [es_username, es_password]}),
                                 "es_host": es_host,
                                 "es_index": es_index
                                }
                   }
    s = Stoq(
            plugin_dir_list=[plugin_home],
            providers=providers,
            connectors=connectors,
            always_dispatch=workers,
            plugin_opts=plugin_opts,
    )
    return s


def init_github_android():
    input_path = os.environ.get("GITHUB_ANDROID_PATH", "/malware/github-android/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="github-android-malware",
                       extra_data={"target": "android", "malicious": "true"}
                       )
    return s, meta


def init_das_malwerk():
    input_path = os.environ.get("DAS_MALWERK_PATH", "/malware/malwerk/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="das-malwerk",
                       extra_data={"malicous": "true"}
                       )
    return s, meta


def init_malshare():
    input_path = os.environ.get("malshare_PATH", "/malware/malshare/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="malshare",
                       extra_data={"malicous": "true"}
                       )
    return s, meta


def init_mbazaar():
    input_path = os.environ.get("MBAZAAR_PATH", "/malware/mbazaar/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="malware-bazaar",
                       extra_data={"malicous": "true"}
                       )
    return s, meta


def init_thezoo():
    input_path = os.environ.get("theZoo_PATH", "/malware/theZoo/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="theZoo",
                       extra_data={"malicous": "true"}
                       )
    return s, meta


def init_urlhaus():
    input_path = os.environ.get("URLHAUS_PATH", "/malware/urlhaus/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="urlhaus",
                       extra_data={"malicous": "true"}
                       )
    return s, meta


def init_vxug():
    input_path = os.environ.get("VXUG_PATH", "/malware/vxug/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="vxug",
                       extra_data={"malicous": "true"}
                       )
    return s, meta


def init_vxvault():
    input_path = os.environ.get("VXVAULT_PATH", "/malware/vxvault/")
    s = make_stoq(input_path)
    meta = RequestMeta(source="vxvault",
                       extra_data={"malicous": "true"}
                       )
    return s, meta


transformer_map = {
    "github-android": init_github_android,
    "das-malwerk": init_das_malwerk,
    "malshare": init_malshare,
    "mbazaar": init_mbazaar,
    "theZoo": init_thezoo,
    "urlhaus": init_urlhaus,
    "vxug": init_vxug,
    "vxvault": init_vxvault
}


def run():
    # configure plugins and outputs here
    transformers = list()

    workers = os.environ.get("TRANSFORMERS", "*")
    if workers == "*":
        for key in transformer_map:
            transformers.append(transformer_map[key]())
    else:
        for worker in workers.split(","):
            if worker in transformer_map:
                transformers.append(transformer_map[worker]())
    loop = asyncio.get_event_loop()

    loop.run_until_complete(asyncio.gather(*[transformer.run(request_meta=meta) for transformer, meta in transformers]))


if __name__ == "__main__":
    run()
