# WebCrypto Liner via WebWorker

> __WARNING__
> WebWorker for Safari, Edge and IR doesn't support WebCrypto API.
> Current example uses it's own getRandomValues implemenation

## Dependency

### Internet Explorer
    
    - `seedrandom`
    - `promise`
    - `elliptic`
    - `asmcrypto`

### Edge, Safari

    - `seedrandom`
    - `elliptic`
    - `asmcrypto`

### Chrome, Firefox

    - no deps

## Size of used libs

| Name            | Size   | Description                          |
|-----------------|--------|--------------------------------------|
| seedrandom      |   2 Kb | Seed for Math.random function        |
| promise         |   5 Kb | Promise implementation               |
| asmcrypto       | 125 Kb | RSA, SHA crypto implementation       |
| elliptic        | 131 Kb | EllipticCurves crypto implementation |
| webcrypto-liner |  63 Kb | WebCrypto API shim                   |