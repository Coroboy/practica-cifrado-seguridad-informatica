/**
 * MODULO 3 - Descifrado y Verificacion por el Receptor (Pedro)
 * Incluye RETO 3: manejo elegante de excepciones.
 *
 * Uso:
 *   node receptor.js              -> descifra con la clave privada de Pedro (caso correcto)
 *   node receptor.js leonora      -> intenta con la clave privada de Leonora (clave incorrecta)
 */
const crypto = require('crypto');
const fs = require('fs');

// Permite elegir con que clave privada se intenta descifrar.
const duenoClave = (process.argv[2] || 'pedro').toLowerCase();
const rutaClavePrivada = `${duenoClave}_privada.pem`;

console.log("==================================================");
console.log(" RECEPTOR - Descifrado y verificacion de firma");
console.log(" Clave privada utilizada: " + rutaClavePrivada);
console.log("==================================================");

// ---- Validaciones previas (evitan que el proceso colapse) ----
if (!fs.existsSync(rutaClavePrivada)) {
  console.error(`[X] No se encontro la clave privada '${rutaClavePrivada}'. Ejecuta primero generar_llaves.js`);
  process.exit(1);
}
if (!fs.existsSync('paquete_transito.json')) {
  console.error("[X] No se encontro 'paquete_transito.json'. Ejecuta primero emisor.js");
  process.exit(1);
}

const llavePrivada = fs.readFileSync(rutaClavePrivada, 'utf8');
const llavePublicaLeonora = fs.readFileSync('leonora_publica.pem', 'utf8');

// ---- Lectura del paquete (puede venir corrupto tras el ataque MITM) ----
let paquete;
try {
  paquete = JSON.parse(fs.readFileSync('paquete_transito.json', 'utf8'));
} catch (error) {
  console.error("[X] El paquete recibido no es un JSON valido. Detalle: " + error.message);
  process.exit(1);
}

const bufferCifrado = Buffer.from(paquete.datosCifrados, 'base64');

// ---- FASE 1: CONFIDENCIALIDAD ----
let mensajeTextoPlano;
try {
  const bufferDescifrado = crypto.privateDecrypt(
    {
      key: llavePrivada,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    bufferCifrado
  );
  mensajeTextoPlano = bufferDescifrado.toString('utf8');
  console.log(`[OK] CONFIDENCIALIDAD: mensaje descifrado -> "${mensajeTextoPlano}"`);
} catch (error) {
  // RETO 3: la excepcion se captura y se traduce a lenguaje de negocio.
  console.error("--------------------------------------------------");
  console.error("[X] FALLO DE CONFIDENCIALIDAD");
  console.error("    No fue posible recuperar el texto en claro.");
  console.error("    Causas posibles:");
  console.error("      a) La clave privada no corresponde a la publica usada para cifrar.");
  console.error("      b) El criptograma fue alterado en transito (padding OAEP invalido).");
  console.error("    Mensaje tecnico de OpenSSL: " + error.message);
  console.error("    El proceso termina de forma controlada, sin volcado de pila.");
  console.error("--------------------------------------------------");
  process.exit(0); // salida limpia: el programa NO colapsa
}

// ---- FASE 2: INTEGRIDAD / NO REPUDIO ----
try {
  const verificador = crypto.createVerify('SHA256');
  verificador.update(mensajeTextoPlano);
  verificador.end();

  const esValido = verificador.verify(llavePublicaLeonora, paquete.firma, 'base64');

  if (esValido) {
    console.log("[OK] INTEGRIDAD CONFIRMADA: el mensaje proviene de Leonora y no fue alterado.");
  } else {
    console.log("--------------------------------------------------");
    console.log("[X] ALERTA DE SEGURIDAD: la firma digital NO coincide.");
    console.log("    El contenido o la firma fueron modificados en transito,");
    console.log("    o el emisor no es realmente Leonora. Paquete DESCARTADO.");
    console.log("--------------------------------------------------");
  }
} catch (error) {
  console.error("[X] No se pudo procesar la firma digital: " + error.message);
}