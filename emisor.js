/**
 * MODULO 2 - Cifrado y Firma Digital por el Emisor (Leonora)
 *
 * CORRECCIONES respecto al archivo original:
 *  - El script entregado cargaba 'bob_publica.pem' y 'alicia_privada.pem',
 *    archivos que generar_llaves.js nunca crea -> error ENOENT.
 *    Se ajusto a pedro/leonora.
 *  - Se declara el padding OAEP de forma explicita para que emisor y
 *    receptor usen exactamente el mismo esquema.
 */
const crypto = require('crypto');
const fs = require('fs');

// 1. Cargar llaves requeridas
const llavePublicaPedro = fs.readFileSync('pedro_publica.pem', 'utf8');
const llavePrivadaLeonora = fs.readFileSync('leonora_privada.pem', 'utf8');

const mensajeOriginal = "REPORTE CONFIDENCIAL: Se ha detectado una vulnerabilidad critica en el servidor central.";

// 2. CIFRADO (Confidencialidad -> Clave PUBLICA del destinatario)
const bufferMensaje = Buffer.from(mensajeOriginal, 'utf8');

// Limite real de RSA-2048 con OAEP/SHA-256: 256 - 2*32 - 2 = 190 bytes.
if (bufferMensaje.length > 190) {
  console.error(`[X] El mensaje mide ${bufferMensaje.length} bytes y el limite es 190.`);
  console.error("    Para datos mas grandes se requiere cifrado hibrido (ver emisor_archivo.js).");
  process.exit(1);
}

const mensajeCifrado = crypto.publicEncrypt(
  {
    key: llavePublicaPedro,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  },
  bufferMensaje
);

// 3. FIRMA DIGITAL (Integridad / No repudio -> Clave PRIVADA del emisor)
const firmador = crypto.createSign('SHA256');
firmador.update(mensajeOriginal);
firmador.end();
const firmaDigital = firmador.sign(llavePrivadaLeonora, 'base64');

// 4. Guardar paquete simulando el envio por un canal inseguro
const paqueteSeguro = {
  datosCifrados: mensajeCifrado.toString('base64'),
  firma: firmaDigital
};

fs.writeFileSync('paquete_transito.json', JSON.stringify(paqueteSeguro, null, 2));

console.log("[+] Mensaje original      : " + mensajeOriginal);
console.log("[+] Tamano en claro       : " + bufferMensaje.length + " bytes");
console.log("[+] Tamano cifrado        : " + mensajeCifrado.length + " bytes (siempre 256 = 2048 bits)");
console.log("[+] Paquete cifrado y firmado escrito en 'paquete_transito.json'");