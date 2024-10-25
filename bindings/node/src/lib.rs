/// Threshold signature protocols.
pub mod protocols;

/// Single party signers.
pub mod signers;

#[cfg(feature = "cggmp")]
#[napi::module_init]
fn init() {
    use napi::bindgen_prelude::create_custom_tokio_runtime;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_start(|| {
            println!("tokio thread started");
        })
        .build()
        .unwrap();
    create_custom_tokio_runtime(rt);
}
