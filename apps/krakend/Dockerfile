FROM krakend:2.12.0
# NOTE: Avoid using :latest image on production. Stick to a major version instead.

COPY krakend.json ./

# Check and test that the file is valid
RUN krakend check -t --lint-no-network -c krakend.json
