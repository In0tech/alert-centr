CREATE DATABASE IF NOT EXISTS alert_center;

CREATE TABLE IF NOT EXISTS alert_center.genie_events (
  ID UInt64,
  STATUS LowCardinality(String),
  UPDATE_TIME DateTime,
  START_TIME DateTime,
  END_TIME Nullable(DateTime),
  MAX_BPS UInt64,
  MAX_PPS UInt64,
  RESOURCE Array(String),
  TARGET_NETWORK IPv4,
  TARGET_BROADCAST IPv4
)
ENGINE = ReplacingMergeTree(UPDATE_TIME)
ORDER BY ID;

CREATE TABLE IF NOT EXISTS alert_center.mitigations_events (
  TARGET_CIDR String,
  CURRENT_MITIGATION Nullable(String),
  UPDATE_TIME DateTime
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(UPDATE_TIME)
ORDER BY (TARGET_CIDR, UPDATE_TIME);

CREATE TABLE IF NOT EXISTS alert_center.kuma_events (
  TARGET_IP IPv4,
  STATUS LowCardinality(String),
  UPDATE_TIME DateTime
)
ENGINE = ReplacingMergeTree(UPDATE_TIME)
ORDER BY (TARGET_IP, UPDATE_TIME);
