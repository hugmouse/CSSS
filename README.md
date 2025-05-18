# Cassandra-based Screenshot Sharing Service (CSSS)

CSSS is a Cassandra-based service that allows users to upload and share their images.

Fault-tolerant, distributed, and scalable. What more could one want from a screenshot-sharing service?

## Installation

To quickly try it out just copy this repo and run `docker compose up`!

This will spin up 3 cassandra instances, 1 frontend and also will apply schemas that are stored in `cql` folder.

Note that Cassandra will take some time to spin up, when all 3 instances will be healthy then `cassandra-init` service
will start applying all migrations stored inside `cql` folder.

### Prerequisites

- Docker + Buildx
- Git

```bash
git clone https://github.com/hugmouse/csss
cd csss
docker network create cassandra
docker compose up -d
```

Now you can navigate to `http://localhost:8080` and use the CSSS!

## Hacking

- Database migrations should be placed at `cql` folder
- Static files (JS, CSS etc.) in `static`
- Go templates in `template`

All the logic is placed inside of `main.go` for simplicity’s sake.
Templates and the CSS are basic for the same reason - you can customize it to your heart's content!

#### Cassandra related

To activate interactive CQLSH, you can do the following:

```sh
docker run -it --rm --network cassandra cassandra cqlsh cassandra-1
```

To simulate a node crash, either disable gossip using `nodetool disablegossip` or stop one of the Cassandra containers.



## Deploying

Remember to change cluster address inside of `main.go` and replication settings as needed.