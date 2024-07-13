FROM php:8.3-cli

RUN apt-get update && apt-get install -y libzip-dev zip unzip

RUN docker-php-ext-install sockets zip

