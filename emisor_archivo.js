/**
 * RETO 1 - Cifrado de archivos adjuntos (esquema HIBRIDO)
 *
 * PROBLEMA: RSA-2048 con OAEP/SHA-256 solo puede cifrar 190 bytes por operacion.
 * Un PDF o una imagen jamas cabe. Intentarlo lanza:
 *   "data too large for key size".
 *
 * SOLUCION (la misma que usan TLS, PGP y S/MIME):
 *   1. Se genera una clave AES-256 aleatoria de un solo uso (clave de sesion).
 *   2. El ARCHIVO se cifra con AES-256-GCM  -> rapido y sin limite de tamano.
 *   3. La CLAVE AES (32 bytes) se cifra con RSA usando la publica de Pedro.
 *   4. El archivo original se firma con la privada de Leonora.
 *
 * Uso: node emisor_archivo.js [ruta_del_archivo]   (por defecto documento.pdf)
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const rutaArchivo = process.argv[2] || 'iris_flowers.pdf';

if (!fs.existsSync(rutaArchivo)) {
  console.error(`[X] No se encontro '${rutaArchivo}'.`);
  console.error("    Copia cualquier PDF o imagen ligera a esta carpeta con ese nombre,");
  console.error("    o ejecuta: node emisor_archivo.js mi_archivo.png");
  process.exit(1);
}

const llavePublicaPedro = fs.readFileSync('pedro_publica.pem', 'utf8');
const llavePrivadaLeonora = fs.readFileSync('leonora_privada.pem', 'utf8');

const datosOriginales = fs.readFileSync(rutaArchivo);
const hashOriginal = crypto.createHash('sha256').update(datosOriginales).digest('hex');

console.log("==================================================");
console.log(" EMISOR (Leonora) - Envio de archivo adjunto");
console.log("==================================================");
console.log(`[i] Archivo   : ${rutaArchivo}`);
console.log(`[i] Tamano    : ${datosOriginales.length} bytes`);
console.log(`[i] SHA-256   : ${hashOriginal}`);

// --- Demostracion del limite de RSA puro (para el reporte) ---
try {
  crypto.publicEncrypt(
    { key: llavePublicaPedro, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    datosOriginales
  );
  console.log("[i] (El archivo era tan pequeno que cabia en una sola operacion RSA.)");
} catch (e) {
  console.log("[i] Prueba de RSA directo sobre el archivo -> FALLA, como se esperaba:");
  console.log("    " + e.message);
  console.log("[i] Por eso se aplica cifrado hibrido.");
}

// --- 1. Clave de sesion simetrica ---
const claveAES = crypto.randomBytes(32); // AES-256
const iv = crypto.randomBytes(12);       // GCM recomienda IV de 12 bytes

// --- 2. Cifrado simetrico del archivo ---
console.time('    tiempo AES-256-GCM');
const cipher = crypto.createCipheriv('aes-256-gcm', claveAES, iv);
const archivoCifrado = Buffer.concat([cipher.update(datosOriginales), cipher.final()]);
const authTag = cipher.getAuthTag(); // etiqueta de autenticacion: integridad del cifrado
console.timeEnd('    tiempo AES-256-GCM');

// --- 3. Cifrado asimetrico SOLO de la clave de sesion ---
console.time('    tiempo RSA (32 bytes)');
const claveAESCifrada = crypto.publicEncrypt(
  { key: llavePublicaPedro, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  claveAES
);
console.timeEnd('    tiempo RSA (32 bytes)');

// --- 4. Firma digital sobre el contenido original ---
const firmador = crypto.createSign('SHA256');
firmador.update(datosOriginales);
firmador.end();
const firmaDigital = firmador.sign(llavePrivadaLeonora, 'base64');

const paquete = {
  nombreArchivo: path.basename(rutaArchivo),
  hashOriginal: hashOriginal,
  claveSesionCifrada: claveAESCifrada.toString('base64'), // protegida por RSA
  iv: iv.toString('base64'),
  authTag: authTag.toString('base64'),
  archivoCifrado: archivoCifrado.toString('base64'),      // protegido por AES
  firma: firmaDigital
};

fs.writeFileSync('paquete_archivo.json', JSON.stringify(paquete, null, 2));

console.log("[+] Clave de sesion AES-256 generada y cifrada con RSA (" + claveAESCifrada.length + " bytes).");
console.log("[+] Archivo cifrado: " + archivoCifrado.length + " bytes.");
console.log("[+] Paquete escrito en 'paquete_archivo.json'.");