FROM debian:jessie
MAINTAINER Cristoffer Fairweather <cfairweather@annixa.com>

# install debian packages
RUN apt-get update && \
    apt-get install -y \
        python \
        python-pip \
        ipython \
    && apt-get clean

# install pip packages
RUN pip install dnslib pg8000 pyDAL

RUN useradd -M dns
RUN usermod -L dns
# copy in the code
COPY code /code
WORKDIR /code

RUN chown dns:dns -R /code
# Need to run as different user
# USER dns



EXPOSE 53/udp
CMD [ "python", "dnsserver.py", "--udp"]