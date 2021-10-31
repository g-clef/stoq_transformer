FROM python:3

RUN apt-get update && apt-get -y install git upx libfuzzy-dev

RUN apt-get install -y p7zip-full unace upx gzip tar

RUN mkdir /app
RUN mkdir /app/plugins
WORKDIR /app

ADD requirements.txt /app
COPY EMBER_format_lief/ /app/EMBER_format_lief
COPY lief/ /app/lief
COPY decompress_dispatch/ /app/decompress_dispatch

RUN pip3 install malwaretl-stoq-transformer==1.0.1

ENV STOQ_HOME=/app

RUN stoq install decompress_dispatch
RUN stoq install --github stoq:dirmon
RUN stoq install --github stoq:es-search
RUN stoq install --github stoq:decompress
RUN stoq install EMBER_format_lief
RUN stoq install --github stoq:entropy
RUN stoq install --github stoq:filedir
RUN stoq install --github stoq:hash
RUN stoq install --github stoq:hash_ssdeep
RUN stoq install lief
RUN stoq install --github stoq:mimetype
RUN stoq install --github stoq:mraptor
RUN stoq install --github stoq:ole
RUN stoq install --github stoq:peinfo
RUN stoq install --github stoq:rtf
RUN stoq install --github stoq:stdout
RUN stoq install --github stoq:symhash
RUN stoq install --github stoq:xdpcarve
RUN stoq install --github stoq:xyz
