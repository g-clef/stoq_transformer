FROM python:3

RUN apt-get update && apt-get -y install git upx

RUN mkdir /app
WORKDIR /app

ADD transformer.py /app

ADD requirements.txt /app

RUN pip3 install -r requirements.txt

RUN stoq install --github stoq:dirmon
RUN stoq install --github stoq:es-search
RUN stoq install --github stoq:decompress
RUN stoq install --github stoq:EMBER_format_lief
RUN stoq install --github stoq:entropy
RUN stoq install --github stoq:hash
RUN stoq install hash_ssdeep
RUN stoq install lief
RUN stoq install --github stoq:mimetype
RUN stoq install --github stoq:mraptor
RUN stoq install --github stoq:ole
RUN stoq install --github stoq:peinfo
RUN stoq install --github stoq:rtf
RUN stoq install --github stoq:symhash
RUN stoq install --github stoq:xdpcarve
RUN stoq install --github stoq:xyz
