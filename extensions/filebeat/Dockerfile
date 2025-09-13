ARG ELASTIC_VERSION

FROM docker.elastic.co/beats/filebeat:${ELASTIC_VERSION:-9.1.2}

# Enable the Zeek module
RUN filebeat modules enable zeek

