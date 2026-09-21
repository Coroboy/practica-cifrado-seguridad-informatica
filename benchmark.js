/**
 * EVIDENCIA PARA EL PILAR DE DISPONIBILIDAD
 * Compara el rendimiento de RSA-2048 contra AES-256-GCM sobre el mismo volumen
 * de datos. Los numeros que imprime este script son los que deben citarse en
 * el reporte escrito.
 *
 * Uso: node benchmark.js
 */
const crypto = require('crypto');
const fs = require('fs');

const llavePublica = fs.readFileSync('pedro_publica.pem', 'utf8');
const llavePrivada = fs.readFileSync('pedro_privada.pem', 'utf8');

const TAM_BLOQUE = 190;         // maximo de RSA-2048 con OAEP/SHA-256
const BLOQUES = 200;            // 200 * 190 = 38,000 bytes (~37 KB)
const datos = crypto.randomBytes(TAM_BLOQUE * BLOQUES);
const opciones = {
  key: llavePublica,
  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256'
};

console.log("==================================================");
console.log(" BENCHMARK: RSA-2048 vs AES-256-GCM");
console.log(` Volumen de datos: ${datos.length} bytes`);
console.log("==================================================");

// --- RSA: hay que trocear en bloques de 190 bytes ---
let inicio = process.hrtime.bigint();
const bloquesCifrados = [];
for (let i = 0; i < BLOQUES; i++) {
  bloquesCifrados.push(
    crypto.publicEncrypt(opciones, datos.subarray(i * TAM_BLOQUE, (i + 1) * TAM_BLOQUE))
  );
}
let msRsaCifrar = Number(process.hrtime.bigint() - inicio) / 1e6;

inicio = process.hrtime.bigint();
for (const bloque of bloquesCifrados) {
  crypto.privateDecrypt({ key: llavePrivada, padding: opciones.padding, oaepHash: 'sha256' }, bloque);
}
let msRsaDescifrar = Number(process.hrtime.bigint() - inicio) / 1e6;

const bytesRsa = bloquesCifrados.reduce((a, b) => a + b.length, 0);

// --- AES sobre exactamente los mismos datos ---
const claveAES = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);

inicio = process.hrtime.bigint();
const cipher = crypto.createCipheriv('aes-256-gcm', claveAES, iv);
const cifradoAES = Buffer.concat([cipher.update(datos), cipher.final()]);
const tag = cipher.getAuthTag();
let msAesCifrar = Number(process.hrtime.bigint() - inicio) / 1e6;

inicio = process.hrtime.bigint();
const decipher = crypto.createDecipheriv('aes-256-gcm', claveAES, iv);
decipher.setAuthTag(tag);
Buffer.concat([decipher.update(cifradoAES), decipher.final()]);
let msAesDescifrar = Number(process.hrtime.bigint() - inicio) / 1e6;

const f = (n) => n.toFixed(2).padStart(10);

console.log("\n                        CIFRAR(ms)  DESCIFRAR(ms)");
console.log("RSA-2048 (200 bloques)" + f(msRsaCifrar) + f(msRsaDescifrar));
console.log("AES-256-GCM (1 pasada)" + f(msAesCifrar) + f(msAesDescifrar));

console.log("\nFactor de lentitud de RSA:");
console.log("  al cifrar   : " + (msRsaCifrar / msAesCifrar).toFixed(1) + "x mas lento");
console.log("  al descifrar: " + (msRsaDescifrar / msAesDescifrar).toFixed(1) + "x mas lento");

console.log("\nExpansion del mensaje (overhead de espacio):");
console.log("  RSA: " + datos.length + " -> " + bytesRsa + " bytes (" +
  ((bytesRsa / datos.length - 1) * 100).toFixed(0) + "% mas)");
console.log("  AES: " + datos.length + " -> " + cifradoAES.length + " bytes (0% mas)");

console.log("\nCONCLUSION: cifrar volumenes grandes solo con RSA degrada el tiempo de");
console.log("respuesta y multiplica el trafico, lo que afecta la DISPONIBILIDAD del");
console.log("servicio. Por eso el asimetrico se reserva para proteger la clave de");
console.log("sesion y el simetrico se encarga de los datos.");