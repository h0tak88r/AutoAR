FROM nginx:alpine

LABEL maintainer="Sandeep Wawdane <contact@thecybersandeep.com>"
LABEL description="ADB Auditor - Professional Android Security Auditing Platform"
LABEL version="1.0.0"

COPY . /usr/share/nginx/html/

RUN rm /usr/share/nginx/html/Dockerfile \
    /usr/share/nginx/html/docker-compose.yml \
    /usr/share/nginx/html/.dockerignore \
    /usr/share/nginx/html/README.md \
    /usr/share/nginx/html/LICENSE \
    /usr/share/nginx/html/CNAME 2>/dev/null || true

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
