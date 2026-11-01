FROM python@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_CONFIG_FILE=/dev/null
COPY release/build-inputs.lock.json release/runtime-wheels.lock /source/release/
COPY control/verify_release.py control/production-profile.schema.json control/verify-release.sh /opt/dracla/
RUN python -I /opt/dracla/verify_release.py fetch-bootstrap
RUN --network=none python -I -m pip --isolated install --no-index --no-deps --only-binary=:all: --require-hashes --no-compile -r /inputs/tools.requirements
RUN rm -rf /inputs /source /root/.cache && chmod 0555 /opt/dracla/verify-release.sh
WORKDIR /
