FROM composer:2 AS composer
FROM php:8.2-cli
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git unzip golang-go gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
WORKDIR /tools
COPY composer.json composer.lock ./
RUN composer install --no-interaction --prefer-dist --no-plugins --no-scripts --no-progress
ENTRYPOINT []
