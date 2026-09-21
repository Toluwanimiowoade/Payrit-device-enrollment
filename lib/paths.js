"use strict";

var os = require("os");
var path = require("path");

var PROJECT_ROOT = path.join(__dirname, "..");

function serverless() {
  return !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.PAYRIT_EPHEMERAL);
}

function writableRoot() {
  return serverless() ? path.join(os.tmpdir(), "payrit-harness") : PROJECT_ROOT;
}

function projectRoot() {
  return PROJECT_ROOT;
}

function pkiDir() {
  return path.join(writableRoot(), ".harness-pki");
}

function runtimeFile() {
  return path.join(writableRoot(), ".runtime.json");
}

function envFile() {
  return path.join(PROJECT_ROOT, ".env.local");
}

module.exports = {
  serverless: serverless,
  writableRoot: writableRoot,
  projectRoot: projectRoot,
  pkiDir: pkiDir,
  runtimeFile: runtimeFile,
  envFile: envFile
};
