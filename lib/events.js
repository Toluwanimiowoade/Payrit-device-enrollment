"use strict";

var httpc = require("./http.js");

var MAX = 300;
var log = [];
var seq = 0;

function record(entry) {
  seq += 1;
  var row = {
    seq: seq,
    at: new Date().toISOString(),
    kind: entry.kind,
    label: entry.label,
    origin: entry.origin || "live",
    method: entry.method || null,
    url: entry.url || null,
    status: typeof entry.status === "number" ? entry.status : null,
    ms: typeof entry.ms === "number" ? entry.ms : null,
    request: entry.request === undefined ? null : entry.request,
    response: entry.response === undefined ? null : entry.response,
    note: entry.note || null
  };
  log.push(row);
  if (log.length > MAX) log = log.slice(log.length - MAX);
  return row;
}

function all(since, raw) {
  var from = Number(since) || 0;
  var rows = log.filter(function (row) {
    return row.seq > from;
  });
  if (raw) return rows;
  return rows.map(function (row) {
    return Object.assign({}, row, {
      request: row.request === null ? null : httpc.abridge(row.request),
      response: row.response === null ? null : httpc.abridge(row.response)
    });
  });
}

function clear() {
  log = [];
}

module.exports = { record: record, all: all, clear: clear };
