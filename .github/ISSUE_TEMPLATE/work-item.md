---
name: Work item
about: One agent-sized unit of design or implementation
title: "<ID>: <imperative summary>"
labels: [agent:proposed]
---
**Type:** design | impl | spike | chore    **Size:** S | M | L    **Runner:** claude | minimax
**Depends on:** <IDs, or none>

## Goal
<one or two sentences: what exists when this is done>

## Context
<ADR sections, reference-pack files, earlier issues>

## Acceptance criteria
- [ ] <observable, testable>

## Out of scope
- <what not to touch>

## Done when
<the single check that proves it, e.g. `go test ./...` passes with the new conformance cases>
