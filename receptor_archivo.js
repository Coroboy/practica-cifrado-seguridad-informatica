/**
 * RETO 1 - Recepcion del archivo adjunto cifrado (esquema HIBRIDO)
 *
 * Pedro: 1) descifra la clave de sesion con su privada RSA,
 *        2) descifra el archivo con esa clave AES,
 *        3) verifica la firma de Leonora,
 *        4) compara el hash para probar que el archivo llego intacto.
 *
 * Uso:
 *   node receptor_archivo.js            -> clave privada de Pedro
 *   node receptor_archivo.js leonora    -> clave incorrecta (demuestra el Reto 3)
 */
const crypto = require('crypto');
const fs = require('fs');

const duenoClave = (process.argv[2] || 'pedro').toLowerCase();
const rutaClavePrivada = `${duenoClave}_privada.pem`;

console.log("==================================================");
console.log(" RECEPTOR (Pedro) - Recepcion de archivo adjunto");
console.log(" Clave privada utilizada: " + rutaClavePrivada);
console.log("==================================================");

if (!fs.existsSync('paquete_archivo.json')) {
  console.error("[X] Falta 'paquete_archivo.json'. Ejecuta primero emisor_archivo.js");
  process.exit(1);
}
if (!fs.existsSync(rutaClavePrivada)) {
  console.error(`[X] Falta '${rutaClavePrivada}'.`);
  process.exit(1);
}

const llavePrivada = fs.readFileSync(rutaClavePrivada, 'utf8');
const llavePublicaLeonora = fs.readFileSync('leonora_publica.pem', 'utf8');
const paquete = JSON.parse(fs.readFileSync('paquete_archivo.json', 'utf8'));

// ---- FASE 1: recuperar la clave de sesion (CONFIDENCIALIDAD) ----
let claveAES;
try {
  claveAES = crypto.privateDecrypt(
    {
      key: llavePrivada,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(paquete.claveSesionCifrada, 'base64')
  );
  console.log("[OK] Clave de sesion AES recuperada con la clave privada RSA.");
} catch (error) {
  console.error("--------------------------------------------------");
  console.error("[X] FALLO DE CONFIDENCIALIDAD");
  console.error("    La clave privada no corresponde a la publica usada para cifrar,");
  console.error("    o la clave de sesion fue alterada en transito.");
  console.error("    Sin la clave AES el archivo es indescifrable.");
  console.error("    Detalle tecnico: " + error.message);
  console.error("--------------------------------------------------");
  process.exit(0);
}

// ---- FASE 2: descifrar el archivo ----
let datosRecuperados;
try {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    claveAES,
    Buffer.from(paquete.iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(paquete.authTag, 'base64'));
  datosRecuperados = Buffer.concat([
    decipher.update(Buffer.from(paquete.archivoCifrado, 'base64')),
    decipher.final() // lanza excepcion si el authTag no cuadra
  ]);
} catch (error) {
  console.error("[X] El archivo cifrado fue manipulado: la etiqueta GCM no coincide.");
  console.error("    Detalle: " + error.message);
  process.exit(0);
}

const nombreSalida = 'recibido_' + paquete.nombreArchivo;
fs.writeFileSync(nombreSalida, datosRecuperados);
console.log(`[OK] Archivo descifrado y guardado como '${nombreSalida}' (${datosRecuperados.length} bytes).`);

// ---- FASE 3: verificar la firma (INTEGRIDAD / NO REPUDIO) ----
const verificador = crypto.createVerify('SHA256');
verificador.update(datosRecuperados);
verificador.end();
const esValido = verificador.verify(llavePublicaLeonora, paquete.firma, 'base64');

// ---- FASE 4: comparacion de hashes ----
const hashRecibido = crypto.createHash('sha256').update(datosRecuperados).digest('hex');
console.log("[i] SHA-256 esperado : " + paquete.hashOriginal);
console.log("[i] SHA-256 obtenido : " + hashRecibido);

if (esValido && hashRecibido === paquete.hashOriginal) {
  console.log("[OK] INTEGRIDAD CONFIRMADA: el archivo llego intacto y fue firmado por Leonora.");
} else {
  console.log("[X] ALERTA: el archivo no coincide con la firma. Contenido comprometido.");
}