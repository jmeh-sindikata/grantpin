# grantd

## Overview

## Architecture

```
┌──────────────┐  socket   ┌───────────────────────────────┐
│ grantd CLI   │──────────▶│ grantd daemon (user-level)     │
│ (agent calls)│◀──────────│  policy → grants → approver    │
└──────────────┘           │  → keystore → spawn → redact   │
┌──────────────┐           │  → audit                       │
│ MCP shim     │──────────▶│                                │
└──────────────┘           └───────────────┬───────────────┘
                                           │ platform backends
                              ┌────────────┴─────────────┐
                              │ KeyStore   │  Approver   │
                              │ (mac/win/  │ (TouchID /  │
                              │  linux)    │ Hello / dlg)│
                              └────────────┴─────────────┘
```

## Install

## Quick start

## MCP configuration

## Limitations
