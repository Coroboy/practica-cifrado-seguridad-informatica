/**
 * RETO 2 - Simulacion de ataque Man-in-the-Middle (MITM)
 *
 * El atacante intercepta 'paquete_transito.json' antes de que llegue a Pedro
 * y modifica UN SOLO caracter. No posee ninguna clave privada.
 *
 * Uso:
 *   node atacante.js firma    -> altera un caracter de la firma digital
 *   node atacante.js datos    -> altera un caracter del criptograma
 *   node atacante.js          -> por defecto altera la firma
 *
 * Los dos casos producen resultados DISTINTOS en el receptor (ver README).
 */
const fs = require('fs');

const objetivo = (process.argv[2] || 'firma').toLowerCase();
const RUTA = 'paquete_transito.json';

if (!fs.existsSync(RUTA)) {
  console.error("[X] No hay paquete que interceptar. Ejecuta primero emisor.js");
  process.exit(1);
}

const paquete = JSON.parse(fs.readFileSync(RUTA, 'utf8'));

// Respaldo del paquete legitimo para poder repetir el experimento.
if (!fs.existsSync('paquete_transito.original.json')) {
  fs.writeFileSync('paquete_transito.original.json', JSON.stringify(paquete, null, 2));
  console.log("[i] Respaldo del paquete legitimo guardado en 'paquete_transito.original.json'");
}

/**
 * Cambia el caracter de la posicion indicada por otro del mismo alfabeto Base64.
 * Asi el string sigue siendo Base64 valido y la alteracion se detecta por
 * criptografia, no por un error de formato.
 */
function alterarUnCaracter(cadena, posicion) {
  const alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const original = cadena[posicion];
  let nuevo = original === 'A' ? 'B' : 'A';
  if (!alfabeto.includes(original)) {
    // Si cayo sobre un '=' de relleno, nos movemos al caracter anterior.
    return alterarUnCaracter(cadena, posicion - 1);
  }
  return {
    cadena: cadena.substring(0, posicion) + nuevo + cadena.substring(posicion + 1),
    original,
    nuevo,
    posicion
  };
}

console.log("==================================================");
console.log(" ATACANTE - Interceptando el canal de comunicacion");
console.log("==================================================");

let resultado;
if (objetivo === 'datos') {
  resultado = alterarUnCaracter(paquete.datosCifrados, 10);
  paquete.datosCifrados = resultado.cadena;
  console.log("[!] Campo alterado: datosCifrados (criptograma RSA)");
} else {
  resultado = alterarUnCaracter(paquete.firma, 10);
  paquete.firma = resultado.cadena;
  console.log("[!] Campo alterado: firma (firma digital SHA256withRSA)");
}

console.log(`[!] Posicion ${resultado.posicion}: '${resultado.original}' -> '${resultado.nuevo}'`);
console.log("[!] Total de bits modificados: unos pocos. Suficiente.");

fs.writeFileSync(RUTA, JSON.stringify(paquete, null, 2));
console.log("[!] Paquete manipulado reenviado hacia Pedro.");
console.log("    Ejecuta ahora: node receptor.js");