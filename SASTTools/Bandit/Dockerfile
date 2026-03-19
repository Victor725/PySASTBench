FROM ubuntu:22.04


SHELL [ "/bin/bash", "-c" ]

ENV SHELL=/bin/bash

RUN apt update &&\
    apt install -y python3 python3-pip python3-venv

RUN python3 -m venv ~/.venvs/bandit &&\
    source ~/.venvs/bandit/bin/activate &&\
    pip install bandit