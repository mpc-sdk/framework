const module = await import("/pkg");
await module.default();

console.log(module.EddsaSigner.random());

// console.log("this is the app running", EddsaSigner);
