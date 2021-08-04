FROM python:3.8-slim-buster
WORKDIR /subcrawl
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y install build-essential gcc yara magic supervisor clamav-daemon clamav-freshclam clamav-unofficial-sigs
COPY requirements.txt requirements.txt
COPY supervisor/supervisord.conf /etc/supervisor/
RUN mkdir /var/log/subcrawl
RUN pip3 install -r requirements.txt
RUN freshclam
EXPOSE 8000
COPY . .
CMD ["bash", "run.sh"]