FROM ubuntu:22.04

RUN apt update &&\
    apt install -y python3.10 python3.10-venv curl

RUN ln -s /usr/bin/python3.10 /usr/bin/python
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py

RUN python -m pip install semgrep

COPY ./rules /rules