FROM ubuntu:22.04

RUN apt update &&\
    apt install -y python3.10 python3.10-venv curl git

RUN ln -s /usr/bin/python3.10 /usr/bin/python
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh

COPY ./bearer-rules-0.48.1 /bearer-rules