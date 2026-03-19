FROM ubuntu:22.04

RUN apt update &&\
    apt install -y wget unzip git python3.10 python3.10-venv

RUN wget https://github.com/github/codeql-cli-binaries/releases/download/v2.20.0/codeql-linux64.zip &&\
   git clone https://github.com/github/codeql.git

# COPY ./codeql-linux64.zip /codeql-linux64.zip
# COPY ./codeql /codeql


RUN unzip /codeql-linux64.zip -d /codeql-cli &&\
    ln -s /codeql-cli/codeql/codeql /bin/codeql