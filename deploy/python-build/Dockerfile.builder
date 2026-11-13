FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS cpython-build

# Build the pinned interpreter without the retired extension.  The two header
# entries removed below are the generated stdlib inventory and internal export
# comments for an extension that is deliberately absent; leaving those names
# in libpython would falsely advertise unavailable runtime modules.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential ca-certificates libbz2-dev libffi-dev libgdbm-dev \
       liblzma-dev libncursesw5-dev libreadline-dev libssl-dev \
       libuuid1 uuid-dev xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:e02d9ac21cebda6e46435369744a92c65cc7cd8669697694122cf97ffacd1e53 \
    https://www.python.org/ftp/python/3.14.9/Python-3.14.9.tar.xz /tmp/Python.tar.xz
RUN mkdir /tmp/Python \
    && tar -xf /tmp/Python.tar.xz -C /tmp/Python --strip-components=1 \
    && rm -rf /tmp/Python/Modules/_sqlite /tmp/Python/Lib/sqlite3 \
    && sed -i '/[Ss][Qq][Ll][Ii][Tt][Ee]/d' \
       /tmp/Python/Modules/Setup /tmp/Python/Modules/Setup.stdlib.in \
       /tmp/Python/Python/stdlib_module_names.h \
       /tmp/Python/Include/internal/pycore_unicodeobject.h \
       /tmp/Python/Include/internal/pycore_pyerrors.h \
    && cd /tmp/Python \
    && ./configure --prefix=/opt/python --enable-shared --without-ensurepip \
       --disable-test-modules --with-lto=no \
    && make -j2 \
    && make install \
    && rm -rf /opt/python/lib/python3.14/test /opt/python/lib/python3.14/ensurepip \
       /opt/python/lib/python3.14/idlelib /opt/python/lib/python3.14/tkinter \
       /opt/python/lib/python3.14/turtledemo /opt/python/lib/python3.14/turtle.py

FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS sdk-files
WORKDIR /source
COPY openepm/ ./openepm/
COPY scripts/build_openepm_sdk_wheel.py ./scripts/build_openepm_sdk_wheel.py
RUN python ./scripts/build_openepm_sdk_wheel.py --source-root /source --destination /wheel \
    && mkdir /sdk \
    && python -m zipfile -e /wheel/openepm_sdk-0.1.0-py3-none-any.whl /sdk

FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS build

RUN rm -rf /usr/local/bin/python* /usr/local/include/python3.14 \
           /usr/local/lib/python3.14 /usr/local/lib/libpython3.14* \
    && rm -f /usr/local/bin/idle* /usr/local/bin/pydoc*
COPY --from=cpython-build /opt/python/ /usr/local/
RUN ln -s python3 /usr/local/bin/python

# The builder receives only the audited public wheel contents. Program source
# and the short-lived build capability are injected by the sandbox launcher.
COPY --from=sdk-files /sdk/openepm/ /usr/local/lib/python3.14/site-packages/openepm/
COPY --from=sdk-files /sdk/openepm_sdk-0.1.0.dist-info/ /usr/local/lib/python3.14/site-packages/openepm_sdk-0.1.0.dist-info/
COPY scripts/check_sandbox_runtime_retirement.py /usr/local/bin/openepm-sandbox-runtime-check
COPY scripts/retire_runtime_packages.sh scripts/prune_python_runtime.py /usr/local/libexec/openepm/
RUN touch /etc/openepm-image-build \
    && bash /usr/local/libexec/openepm/retire_runtime_packages.sh app \
    && python /usr/local/libexec/openepm/prune_python_runtime.py \
    && rm -rf /usr/local/libexec/openepm /etc/openepm-image-build \
    && chmod 0555 /usr/local/bin/openepm-sandbox-runtime-check \
    && python /usr/local/bin/openepm-sandbox-runtime-check --probe-current-runtime /

FROM scratch
COPY --from=build / /
ENV PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python", "-I", "-m", "openepm.builder_runtime"]
