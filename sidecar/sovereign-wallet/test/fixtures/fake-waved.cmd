@echo off
rem Windows wrapper so the sidecar can spawn the fake waved as a "binary".
node "%~dp0fake-waved.mjs" %*