FROM ubuntu:22.04

SHELL [ "/bin/bash", "-c" ]

ENV SHELL=/bin/bash

RUN apt update &&\
    apt install -y python3.10 python3.10-venv


RUN python3.10 -m venv ~/.venvs/dlint &&\
    source ~/.venvs/dlint/bin/activate &&\
    pip install dlint
