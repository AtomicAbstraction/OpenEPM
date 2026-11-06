ARG KEYCLOAK_BASE_IMAGE
FROM ${KEYCLOAK_BASE_IMAGE} AS build

ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true
RUN /opt/keycloak/bin/kc.sh build
USER 0:0
RUN java_home=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")") \
    && cp -aL "$java_home" /opt/java-runtime

FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS runtime
RUN groupadd --gid 1000 keycloak \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin keycloak
COPY --from=build /opt/keycloak/ /opt/keycloak/
COPY --from=build /opt/java-runtime/ /opt/java-runtime/
COPY --chmod=0555 deploy/identity/openepm-keycloak-entrypoint.sh /opt/openepm/bin/openepm-keycloak-entrypoint
COPY scripts/retire_runtime_packages.sh scripts/prune_python_runtime.py /usr/local/libexec/openepm/
COPY --chmod=0555 scripts/check_runtime_retirement.sh /usr/local/bin/openepm-runtime-check
RUN touch /etc/openepm-image-build \
    && bash /usr/local/libexec/openepm/retire_runtime_packages.sh app \
    && python /usr/local/libexec/openepm/prune_python_runtime.py \
    && rm -rf /usr/local/libexec/openepm /etc/openepm-image-build \
       /usr/local/bin/python* /usr/local/include/python3.14 \
       /usr/local/lib/python3.14 /usr/local/lib/libpython3.so /usr/local/lib/libpython3.14* \
    && find /opt/java-runtime -type f -name libjsound.so -delete \
    && LD_LIBRARY_PATH=/opt/java-runtime/lib:/opt/java-runtime/lib/server \
       bash /usr/local/bin/openepm-runtime-check
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    JAVA_HOME=/opt/java-runtime \
    LD_LIBRARY_PATH=/opt/java-runtime/lib:/opt/java-runtime/lib/server \
    PATH=/opt/java-runtime/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 1000:1000
ENTRYPOINT ["/opt/openepm/bin/openepm-keycloak-entrypoint"]
