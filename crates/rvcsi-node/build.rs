//! napi-rs build glue (ADR-096): emits the platform link args the `.node`
//! addon needs and (re)generates `index.d.ts` / `index.js` via `napi build`.
fn main() {
    napi_build::setup();
}
