#!/bin/bash

# Wait for Cassandra 1 to be alive
until cqlsh cassandra-1 -e 'DESCRIBE KEYSPACES' > /dev/null 2>&1; do
  echo 'Waiting for Cassandra to be ready...'
  sleep 5
done

# Apply all .cqls
for f in /cql/schema_version_*.cql; do
  echo "Applying schema: $f"
  if ! cqlsh cassandra-1 -f "$f"; then
    echo "Failed to apply schema: $f" >&2
    exit 1
  fi
done
