FROM python:3.6-slim

LABEL maintainer="karen.florykian@dowjones.com,igor.bakalo@dowjones.com"

ENV appDir /code
ENV GIT_SSL_NO_VERIFY 1
ENV OPEN_SOURCE_CONFIGURATION_ORIGIN LocalPath
ENV CX_WSDL_VERSION v7
ENV DEPENDENCY_CHECK_VERSION 3.3.0
ENV NPM_REGISTRY https://registry.npmjs.org
ENV MASK_PERCENT 0.7
ENV MAX_TOKEN_LEN 5
ENV SBT_VERSION 0.13.15

RUN mkdir -p /usr/share/man/man1 && \
    apt-get -qq update && apt-get install -q -y --no-install-recommends \
    unzip \
    curl \
    wget \
    openjdk-11-jdk \
    apt-transport-https \
    rsync \
    git \
    python3-pip \
    python3-setuptools \
    zlib1g-dev \
    lsb-release \
    gnupg \
    dirmngr \
    maven && \
    apt-get clean && \
    apt-get autoremove --purge && \
	rm -rf /var/lib/apt/lists/*

# Install NodeJS
## Adding the NodeSource signing key to your keyring...
RUN wget -qO- https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add -
## Creating apt sources list file for the NodeSource Node.js 10.x repo...
RUN echo 'deb https://deb.nodesource.com/node_10.x stretch main' > /etc/apt/sources.list.d/nodesource.list
RUN echo 'deb-src https://deb.nodesource.com/node_10.x stretch main' >> /etc/apt/sources.list.d/nodesource.list
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs && \
    apt-get clean && \
    apt-get autoremove --purge && \
	rm -rf /var/lib/apt/lists/*

RUN npm -g i n && n 10 --test
RUN npm -g i npm@6.1 snyk@1.110.2 --test

RUN echo "deb https://dl.bintray.com/sbt/debian /" | tee -a /etc/apt/sources.list.d/sbt.list
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 2EE0EA64E40A89B84B2DF73499E82A75642AC823
RUN apt-get update && \
    apt-get install -y sbt --no-install-recommends && \
    apt-get clean && \
    apt-get autoremove --purge && \
	rm -rf /var/lib/apt/lists/*

RUN mkdir -p ~/.sbt/0.13/plugins && mkdir -p ~/.sbt/1.0/plugins
RUN echo "addSbtPlugin(\"net.virtual-void\" % \"sbt-dependency-graph\" % \"0.9.2\")" > ~/.sbt/0.13/plugins/plugins.sbt
RUN echo "addSbtPlugin(\"net.virtual-void\" % \"sbt-dependency-graph\" % \"0.9.2\")" > ~/.sbt/1.0/plugins/plugins.sbt

# Installing Python Dependencies

RUN pip3 install --upgrade pip && \
    pip3 install bandit==1.5.1 junit-xml==1.8 requests==2.21.0 zeep==2.5.0 PyYAML==3.12 bs4==0.0.1 \
    slackclient==1.2.1 jira==1.0.15 configparser==3.5.0 PyJWT==1.6.4 cryptography==2.2.2 \
    xmltodict==0.11.0 junit2html==21 && \
    pip3 install https://github.com/reportportal/client-Python/archive/3.2.2.zip

# Creating code directory

RUN mkdir ${appDir}

COPY bugbar /tmp/bugbar
COPY sast_controller /tmp/sast_controller
ADD ./setup.py /tmp/setup.py
RUN cd /tmp && python3 setup.py install

WORKDIR ${appDir}
ADD ./entrypoint.sh /tmp/entrypoint.sh
RUN chmod +x /tmp/entrypoint.sh

ENTRYPOINT ["/tmp/entrypoint.sh"]