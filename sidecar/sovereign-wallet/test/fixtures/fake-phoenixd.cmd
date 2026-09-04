rem Windows wrapper so the test harness can spawn the fake phoenixd node
rem as a child process (the phoenixd rail is client-only — the sidecar does
rem NOT spawn the node; the test owns the fixture lifecycle).
node "%~dp0fake-phoenixd.mjs" %*