FROM php:7.2-cli@sha256:5249d94b4b00db63a0ed53e6528114926110ab5dcb0d0f07cc30d1ea7dbe747e

ENV DEBIAN_FRONTEND=noninteractive

RUN printf 'deb https://archive.debian.org/debian buster main\n' > /etc/apt/sources.list \
    && printf 'deb https://archive.debian.org/debian-security buster/updates main\n' >> /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git unzip \
    && docker-php-ext-install mbstring \
    && rm -rf /var/lib/apt/lists/*

ARG COMPOSER_SHA256=28dbb6bd8bef31479c7985b774c130a8bda37dbe63c35b56f6cb6bc377427573
ARG COMPOSER_URL=https://getcomposer.org/download/2.8.10/composer.phar

RUN curl -fsSL -o /usr/local/bin/composer "${COMPOSER_URL}" \
    && echo "${COMPOSER_SHA256}  /usr/local/bin/composer" | sha256sum -c - \
    && chmod +x /usr/local/bin/composer

WORKDIR /app
