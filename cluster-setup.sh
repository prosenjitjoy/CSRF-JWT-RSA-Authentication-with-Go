#!/bin/bash

set -o errexit
set -o errtrace
set -o nounset
set -o pipefail


if [ -z "$(command -v podman)" ]; then
  echo "ERR: podman is not installed"
  echo "RUN: sudo apt install podman"
  exit 1
fi

podman network create cluster

podman run --name node1 --network cluster --hostname node1 -v ./cassandra.yaml:/etc/cassandra/cassandra.yaml -p 127.0.0.1:9042:9042 -m 1.7G -d cassandra:latest && sleep 70

podman run --name node2 --network cluster --hostname node2 -v ./cassandra.yaml:/etc/cassandra/cassandra.yaml -p 127.0.0.2:9042:9042 -e CASSANDRA_SEEDS=node1 -m 1.7G -d cassandra:latest && sleep 70

podman run --name node3 --network cluster --hostname node3 -v ./cassandra.yaml:/etc/cassandra/cassandra.yaml -p 127.0.0.3:9042:9042 -e CASSANDRA_SEEDS=node1,node2 -m 1.7G -d cassandra:latest && sleep 70

podman exec -it node1 nodetool status
