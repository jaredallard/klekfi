# [WIP] klefki

## User Stories

- As a server operator, I want to utilize full disk encryption without
  needing to decrypt every drive manually after every restart.
- As a server operator, I want to know my full disk encryption keys are
  not stored on disk in plain-text, rendering the encryption useless.
- As a server operator, I wish to be able to store my FDE keys wherever
  I would like to.

## High-level Overview

Klekfi provides the following:

- gRPC API for fetching keys used to decrypt a single FDE device.
  Multiple devices is out of scope.

## gRPC API

### Authorization

Authorization is determined by a private key issued for each caller.
This private key is used to determine which machine is which.

While the key is "private", it should always be assumed that it could be
an attacker using it, as it will need to be stored readily accessible on
disk.

### Endpoints

- `GetKey() string` - Creates a new session for the authenticated
  machine, waits for `SubmitKey` to be called, then returns the
  plain-text pass-phrase.
- `ListSessions() []MachineID` - Returns a list of machine IDs waiting
  for a key to be provided.
- `SubmitKey(key string, machineID string)` - Finds the active sessions
  for the provided `machineID` and submits the key to it.

### Security

- Pass-phrases are encrypted using to public key of the authenticated
  machine to prevent the pass-phrase from ever being send unencrypted or
  being able to decrypted the key.
- Machine IDs are derived from the authenticated machine, through a
  signature check (public keys are stored on the server side).

### Flow

1. Machine A boots initramfs+kernel
2. Machine A calls `GetKey()`

## Machine Registration

Adding a new machine requires the generation of a new private key. This
can be done through `klekfictl`. Example usage:

```bash
klefkictl new
```

This will create a new entry in `data/klefkictl.sql`.
