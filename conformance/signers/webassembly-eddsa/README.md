# EdDSA Signing Test

## Prerequisites

* Node >= v20.11.0
* Rust toolchain (stable channel >= 1.82.0)
* wasm-pack >= 0.13.0

## Setup

Install dependencies and browsers:

```
npm install
npx playwright install
```

Build and copy the webssembly bindings:

```
npm run build
```

Start a development server:

```
npm run dev
```

Run the tests:

```
npm test
```