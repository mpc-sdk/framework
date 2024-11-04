import {
  Worker, isMainThread, parentPort, workerData,
} from 'node:worker_threads';

const scripts = [
  './tests/p1.js',
  './tests/p2.js',
  './tests/p3.js',
];

console.log("Testing ...");

for (const fileName of scripts) {
  console.log(fileName);
  const worker = new Worker(fileName);
}

// const workers = scripts.map((fileName) => new Worker(fileName));

