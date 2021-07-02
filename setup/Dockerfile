FROM python:3

RUN apt-get update && apt-get -y upgrade

RUN mkdir /app

ADD setup_stoq.py /app

ADD requirements.txt /app

RUN pip3 install -r /app/requirements.txt

CMD ["python3", "/app/setup_stoq.py"]