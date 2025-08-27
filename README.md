# c2-beacon-detection


suzue@ubun2:~/vdt2/docker-elk$ docker compose exec elasticsearch bin/elasticsearch-reset-password --batch --user elastic
WARNING: Owner of file [/usr/share/elasticsearch/config/users] used to be [root], but now is [elasticsearch]
WARNING: Owner of file [/usr/share/elasticsearch/config/users_roles] used to be [root], but now is [elasticsearch]
Password for the [elastic] user successfully reset.
New value: GXD5YKdLzyhiidmbgsRb
suzue@ubun2:~/vdt2/docker-elk$ docker compose exec elasticsearch bin/elasticsearch-reset-password --batch --user logstash_internal
Password for the [logstash_internal] user successfully reset.
New value: k0-MaLNzo*1lOI8VmuyM
suzue@ubun2:~/vdt2/docker-elk$ docker compose exec elasticsearch bin/elasticsearch-reset-password --batch --user kibana_system
Password for the [kibana_system] user successfully reset.
New value: ISMY-YsvW+3oHZjb1C_O


p, [::]:9300->9300/tcp                                                                                                     docker-elk-elasticsearch-1
suzue@ubun2:~/vdt2/elk_docker$ docker exec -it dbaeaae99b59 bin/kibana-encryption-keys generate
## Kibana Encryption Key Generation Utility

The 'generate' command guides you through the process of setting encryption keys for:

xpack.encryptedSavedObjects.encryptionKey
    Used to encrypt stored objects such as dashboards and visualizations
    https://www.elastic.co/guide/en/kibana/current/xpack-security-secure-saved-objects.html#xpack-security-secure-saved-objects

xpack.reporting.encryptionKey
    Used to encrypt saved reports
    https://www.elastic.co/guide/en/kibana/current/reporting-settings-kb.html#general-reporting-settings

xpack.security.encryptionKey
    Used to encrypt session information
    https://www.elastic.co/guide/en/kibana/current/security-settings-kb.html#security-session-and-cookie-settings

Already defined settings are ignored and can be regenerated using the --force flag.  Check the documentation links for instructions on how to rotate encryption keys.
Definitions should be set in the kibana.yml used configure Kibana.

Settings:
xpack.encryptedSavedObjects.encryptionKey: b6b0c1b405a94294a810bf2152417a44
xpack.reporting.encryptionKey: 50827ecef285a2d73399ec183a51c385
xpack.security.encryptionKey: 52fb6a469af1a22f64c06b154f8a7cdf

--------

curl -u elastic:changeme -X PUT "http://localhost:9200/_index_template/pcap-c2-template" \
-H 'Content-Type: application/json' -d <file>

docker exec -it b41110eb9bde bin/elasticsearch-reset-password -u kibana_system -i