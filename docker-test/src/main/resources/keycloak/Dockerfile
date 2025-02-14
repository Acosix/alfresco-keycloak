FROM ${keycloak.docker.image}:${keycloak.docker.version}

COPY test-realm.json /opt/keycloak/data/import/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]