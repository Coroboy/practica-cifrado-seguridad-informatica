# practica-cifrado-seguridad-informatica

Reto 1 — Cifrado de archivo adjunto (PDF)
bash
node generar_llaves.js      # si no las tienes ya generadas
node emisor_archivo.js      # cifra documento.pdf con AES+RSA híbrido
node receptor_archivo.js    # lo descifra y compara el hash SHA-256


Reto 2 — Ataque Man-in-the-Middle
Caso A: alterar la firma

bash
node emisor.js
node atacante.js firma
node receptor.js

Caso B: alterar los datos cifrados
bash
node emisor.js
node atacante.js datos
node receptor.js

Reto 3 — Manejo de excepciones (clave incorrecta)
bash
node emisor.js
node receptor.js leonora

bash
node benchmark.js