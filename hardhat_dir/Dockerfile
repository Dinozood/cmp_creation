FROM debian:latest
LABEL authors="dinozood"

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN mkdir /root/project
WORKDIR /root/project
ADD * ./

RUN apt-get update \
    && apt-get install -y wget \
    npm \
    curl \
    git \
    zip \
    && apt-get autoclean


ENV NODE_VERSION 16
ENV NVM_DIR /usr/local/nvm

RUN curl --silent -o- https://raw.githubusercontent.com/creationix/nvm/v0.31.2/install.sh | bash
RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

RUN npm init -y
RUN npm install --save-dev hardhat
RUN npm install --save-dev @nomicfoundation/hardhat-toolbox@^4.0.0

RUN unzip base.zip
ENV SEED_PHRASE "crop draw depend total kite hip again badge slice aisle cover spell"

RUN npx hardhat compile
RUN npx hardhat test
RUN npx hardhat run scripts/deploy.js
CMD npx hardhat node