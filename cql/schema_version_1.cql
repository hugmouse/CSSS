CREATE KEYSPACE db WITH REPLICATION = {
    'class': 'NetworkTopologyStrategy',
    'my-datacenter-1': 3
};

CREATE TABLE IF NOT EXISTS db.screenshots
(
    screenshot_id TIMEUUID,
    user_id       UUID,
    username      text,
    data          blob,
    type          text,
    PRIMARY KEY (screenshot_id, user_id, username)
);

CREATE TABLE IF NOT EXISTS db.users
(
    user_id       UUID,
    username      text,
    password_hash text,
    PRIMARY KEY ( user_id, username )
);
