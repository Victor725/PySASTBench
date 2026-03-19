FROM ubuntu:22.04


SHELL [ "/bin/bash", "-c" ]

ENV SHELL=/bin/bash

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update &&\
    apt install -y git curl build-essential python3.10 python3.10-venv expect

RUN echo aaa > /.dockerenv

RUN curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh > ./install_brew.sh &&\
    chmod +x ./install_brew.sh &&\
    NONINTERACTIVE=1 ./install_brew.sh

#RUN (echo; echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"') >> /root/.bashrc
#RUN eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
ENV PATH=/home/linuxbrew/.linuxbrew/bin:$PATH

RUN brew install watchman

RUN rm /.dockerenv

COPY ./sapp /sapp

COPY ./filter.json /filter.json

RUN python3.10 -m venv ~/.venvs/pyre &&\
    source ~/.venvs/pyre/bin/activate &&\
    pip install pyre-check click==8.1.7 &&\
    cd /sapp &&\
    pip install -U pip setuptools &&\
    pip install -r requirements.txt &&\
    python setup.py install

