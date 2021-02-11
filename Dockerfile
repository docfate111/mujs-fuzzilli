FROM ubuntu:18.04

RUN apt update -y && \
    apt install -y git wget libcurl4 libpython2.7 libpython2.7-dev libreadline-dev clang libicu-dev  libcurl4-openssl-dev && \
    wget https://swift.org/builds/swift-5.0-release/ubuntu1804/swift-5.0-RELEASE/swift-5.0-RELEASE-ubuntu18.04.tar.gz && \
    tar xzf swift-5.0-RELEASE-ubuntu18.04.tar.gz && \
    mv swift-5.0-RELEASE-ubuntu18.04 /usr/share/swift && \
    echo "export PATH=/usr/share/swift/usr/bin:$PATH" >> ~/.bashrc && \
    /bin/bash -c "source  ~/.bashrc" && \
    wget https://github.com/googleprojectzero/fuzzilli/archive/v0.9.1.tar.gz && \
    tar xzf v0.9.1.tar.gz && \
    cd / && \
    git clone https://github.com/docfate111/mujs-fuzzilli.git && \
    cd mujs-fuzzilli && \
    make
    #cd /fuzzilli && \
    #swift build
    # swift run FuzzilliCli build/release/mujs

