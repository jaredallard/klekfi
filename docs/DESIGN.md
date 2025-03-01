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

- `GetKey() string` - If connected to a client through
  `SubmitKey`, returns the key, otherwise waits for a period of time
  then the caller should retry the endpoint (polling).
- `ListSessions() []MachineID` - Returns a list of machine IDs waiting
  for a key to be provided.
- `SubmitKey(key []byte, machineID string)` - If a session is present
  for the provided `machineID`, then the key is stored in memory on the
  server side and provided when `GetKey` is next called by the machine.
  Note that `key` is expected to be encrypted to the `machineID`'s
  public key, which is obtained through `ListSessions` beforehand.

### Security

- Pass-phrases are encrypted to public key of the authenticated machine
  to prevent the pass-phrase from ever being sent unencrypted or being
  able to decrypted the key.
- Machine IDs are derived from the authenticated machine, through a
  signature check (public keys are stored on the server side).
  - This technically is vulnerable to replay attacks. However, the
    returned data is encrypted to the key holder. An attacker replaying
    this would get encrypted data only.

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
