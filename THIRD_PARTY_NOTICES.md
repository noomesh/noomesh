# Third-party notices

noomesh is licensed under the terms in [LICENSE](LICENSE). This file lists
third-party material that is copied or adapted into this repository, with
its notice. Dependencies that are installed rather than copied are covered by
their own licences, recorded in the lockfiles listed at the end.

## shadcn/ui

The following files are derived from shadcn/ui:

- `ui/apps/web/src/components/ui/button.tsx`
- `ui/apps/web/src/components/ui/card.tsx`
- `ui/apps/web/src/components/ui/input.tsx`
- `ui/apps/web/src/components/ui/dropdown-menu.tsx`

```
MIT License

Copyright (c) 2023 shadcn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Docker Hardened Images (Community)

The container images published under `ghcr.io/noomesh/dhi/*`, and the gateway,
node-agent and postgres images built `FROM` them, contain layers from Docker
Hardened Images (DHI) Community (`dhi.io`). DHI Community images are
licensed under the Apache License, Version 2.0
(<https://www.apache.org/licenses/LICENSE-2.0>), Copyright Docker, Inc. and
the authors of the packaged open-source software, each under its own licence.
The DHI bases are mirrored unmodified and stay public; the list is
`scripts/dhi-images.txt`.

## Dependencies

The exact versions of every installed dependency, from which their licences
can be read, are pinned in:

- `gateway-rust/Cargo.lock` and `noo-cli/Cargo.lock` (Rust)
- `node-agent-go/go.sum` (Go)
- `ui/package-lock.json` (JavaScript / TypeScript)
