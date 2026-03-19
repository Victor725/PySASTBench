FROM ubuntu:22.04

RUN apt update &&\
    apt install -y aspnetcore-runtime-8.0 python3.10 python3.10-venv

RUN ln -s /usr/bin/python3.10 /usr/bin/python

COPY ./DevSkim_CLI_linux_1.0.59 /DevSkim