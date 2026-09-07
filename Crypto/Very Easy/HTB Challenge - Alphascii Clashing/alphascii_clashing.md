HTB Challenge - alphascii clashing

Dificultad:
Release:

Very Easy

25-09-2024

Skills Required

  Basic Python source code analysis
  Know  how  to  research  with  the  right  keywords

based on the hints provided.

Skills Learned

  Learn  about  MD5  collisions  produced  by

alphanumeric inputs.

La presente evaluación técnica aborda el análisis de un servicio de autenticación minimalista cuya lógica
interna presenta una vulnerabilidad criptográfica de alto impacto derivada del uso de la función hash MD5
en ausencia de controles de integridad y validación estructural. El servicio implementa un mecanismo de
registro y autenticación basado en la comparación estricta entre el hash del identificador de usuario y la
contraseña suministrada, lo que genera una dependencia directa entre la solidez del algoritmo de hashing y
la robustez del flujo de control.

La debilidad inherente de MD5 frente a colisiones controladas permite construir un escenario en el que dos
identificadores  distintos  producen  un  digest  idéntico,  provocando  una  inconsistencia  lógica  durante  el
proceso  de  autenticación.  Esta  discrepancia,  correctamente  orquestada,  fuerza  la  ejecución  de  una  ruta
defectuosa  que  culmina  en  la  terminación  abrupta  de  la  aplicación  y  en  la  exposición  de  información
sensible.

La explotación se articula mediante la generación de una colisión MD5 alfanumérica y la posterior inserción
de dos registros construidos de forma deliberada, cada uno con un nombre de usuario distinto, pero con el
mismo digest y una contraseña común. La autenticación con el segundo de estos usuarios desencadena la
evaluación del primer registro coincidente, generando una divergencia entre el nombre de usuario en texto
claro y el hash validado.

Esta condición activa el comportamiento anómalo del servicio y permite obtener el artefacto final asociado
a  la  vulnerabilidad.  El  análisis  demuestra,  en  última  instancia,  cómo  la  ausencia  de  mecanismos  de
endurecimiento criptográfico y de validación coherente de identidad puede derivar en fallos lógicos críticos
incluso en aplicaciones de complejidad reducida.

7 de septiembre de 2026

1

Enumeration

En  el  contexto  de  esta  evaluación,  el  escenario  de  ataque  se  articula  alrededor  de  un  único  artefacto
proporcionado por la plataforma: el fichero server.py, que constituye el servicio Python desplegado en la
instancia remota y actúa como superficie primaria de interacción. La concisión del código fuente facilita
un análisis estático exhaustivo desde las primeras fases del ejercicio, permitiendo identificar con rapidez la
lógica de negocio, los mecanismos de autenticación y las estructuras internas de persistencia.

Analyzing the source code

El script inicializa una base de datos mínima sustentada en un diccionario en memoria, dentro del cual se
encuentran predefinidos dos usuarios registrados. El propio comentario incluido por el desarrollador revela
la  estructura  de  almacenamiento  empleada,  evidenciando  un  modelo  simplificado  que  prescinde  de
cualquier capa de abstracción, validación o control de integridad. Esta precariedad arquitectónica anticipa
la  posibilidad  de  vectores  de  explotación  derivados  de  la  ausencia  de  controles  propios  de  entornos
productivos.

A continuación, el código expone la función get_option(), responsable de presentar el menú principal y de
orquestar el flujo de ejecución mediante tres rutas funcionales: autenticación, registro de nuevos usuarios
y  terminación  de  la  sesión.  Esta  interfaz  rudimentaria  constituye  el  punto  de  entrada  para  todas  las
operaciones  del  servicio  y,  por  tanto,  el  eje  desde  el  cual  se  articula  la  interacción  del  atacante  con  la
aplicación vulnerable.

El cuerpo central del método principal articula la lógica de control del flujo de ejecución, delegando en
funciones  específicas  la  gestión  de  los  procesos  de  registro  y  autenticación.  Para  comprender
adecuadamente el comportamiento de la aplicación, resulta pertinente examinar de manera aislada cada una
de estas rutas funcionales, comenzando por el procedimiento de registro. En esta fase, el servicio solicita al
usuario la provisión de sus credenciales en formato JSON, concretamente un par compuesto por nombre de
usuario y contraseña.

El código impone una restricción explícita sobre ambos campos mediante la condición usr.isalnum() and
pwd.isalnum(), lo que obliga a que tanto el identificador como la clave sean estrictamente alfanuméricos.
Esta limitación, aparentemente inocua, adquiere una relevancia estratégica en el contexto del desafío, pues
delimita  el  espacio  de  búsqueda  y  orienta  la  investigación  hacia  vectores  de  explotación  asociados  a
funciones hash  y colisiones controladas. Una vez verificada la naturaleza alfanumérica de  los valores y
constatado que el nombre de usuario no existe previamente en la base de datos, el sistema procede a registrar
la nueva entrada, almacenando el hash MD5 del nombre de usuario junto con la contraseña en texto claro,
conforme al formato descrito en los comentarios de inicialización.

7 de septiembre de 2026

2

El flujo de autenticación reproduce parcialmente la estructura anterior: nuevamente se solicita al usuario la
entrega  de  sus  credenciales  en  JSON  y,  acto  seguido,  se  calcula  el  hash  MD5  del  nombre  de  usuario
proporcionado. A partir de este punto, el servicio itera secuencialmente sobre los registros existentes en la
base  de datos,  comparando  el  hash  del  nombre  de  usuario y  la  contraseña  suministrada con  los valores
almacenados. Si ambos coinciden con los de algún registro, la aplicación evalúa una segunda condición: la
correspondencia entre el nombre de usuario en texto claro y el valor almacenado en dicho registro. En caso
de coincidencia plena, el usuario es autenticado con éxito. Sin embargo, si el hash y la contraseña coinciden,
pero el nombre de usuario en texto claro difiere, la aplicación entra en un estado anómalo que desencadena
su terminación inmediata y, como efecto colateral, la exposición de la flag.

Este comportamiento constituye el núcleo explotable del servicio. Para provocar la finalización abrupta del
proceso y obtener la flag, es necesario suministrar un par de credenciales que satisfaga simultáneamente
dos  condiciones:  por  un  lado,  que  el  hash  MD5  del  nombre  de  usuario  proporcionado  y  la  contraseña
coincidan con los valores almacenados en algún registro de la base de datos; por otro, que el nombre de
usuario en texto claro no coincida con el asociado a dicho registro.

La contraseña, en este contexto, carece de restricciones adicionales más allá de su presencia en la base de
datos, lo que simplifica el vector de ataque y concentra la complejidad en la manipulación del hash del
identificador. En consecuencia, el objetivo del desafío puede sintetizarse en la necesidad de construir un
nombre de usuario cuyo hash MD5 coincida con el de un registro existente, pero cuyo valor en texto claro
difiera del almacenado, provocando así la condición de inconsistencia que fuerza la terminación del servicio
y la consiguiente filtración de la flag.

Finding the vulnerability

La  condición  necesaria  para  desencadenar  el  comportamiento  anómalo  del  servicio  —esto  es,  la
terminación  abrupta  de  la  aplicación  y  la  consiguiente  exposición  de  la  flag—  exige  que  el  nombre  de
usuario almacenado en el registro seleccionado difiera del valor suministrado por el atacante, aun cuando
el hash MD5 de ambos sea idéntico. Esta premisa implica, de manera inmediata, que la base de datos debe
contener al menos dos  entradas adicionales creadas  por  el  propio atacante,  cada una con  un  nombre de
usuario distinto, pero con un hash MD5 coincidente. Además, ambas entradas deben compartir la misma
contraseña, dado que la verificación de autenticación se articula mediante la comparación estricta del par
[usr_hash, pwd] con el registro correspondiente.

7 de septiembre de 2026

3

En una primera aproximación, esta condición podría parecer de difícil consecución; sin embargo, el propio
enunciado  del  desafío  y  la  elección  de  la  función  hash  utilizada  orientan  claramente  la  estrategia  de
explotación. Es sobradamente conocido que MD5 presenta debilidades criptográficas severas, entre ellas la
posibilidad  de  construir  pares  de  entradas  distintas  𝑥 ≠ 𝑦 tales  que  𝐻(𝑥) = 𝐻(𝑦) .  Esta  propiedad,
ampliamente documentada en la literatura de seguridad, se convierte aquí en el vector de ataque esencial.

El  objetivo  del  desafío,  por  tanto,  se  alinea  de  manera  directa  con  la  definición  clásica  de  colisión:
identificar dos cadenas alfanuméricas distintas cuyo hash MD5 sea idéntico y que puedan ser registradas
en  la  base  de  datos  con  una  misma  contraseña.  Una  vez  creados  ambos  registros,  el  atacante  puede
autenticarse utilizando uno de los nombres de usuario colisionados y la contraseña compartida, provocando
que el sistema detecte la coincidencia del hash y de la clave, pero no la del nombre de usuario en texto claro.
Esta discrepancia lógica activa la ruta de ejecución defectuosa que culmina en la finalización del servicio
y la revelación de la flag.

Finding alphanumeric MD5 collisions

La literatura técnica recoge múltiples ejemplos de colisiones MD5 construidas de forma deliberada, y uno
de los más citados demuestra la existencia de pares de entradas distintas que producen idénticos digestos.
No obstante, dichos ejemplos suelen estar compuestos por secuencias arbitrarias de bytes, muchas de las
cuales no son representables en ASCII y, por tanto, resultan incompatibles con las restricciones impuestas
por la aplicación analizada, que exige que tanto el nombre de usuario como la contraseña sean estrictamente
alfanuméricos.

Esta  limitación  obliga  a  acotar  la  búsqueda  a  colisiones  MD5  construidas  exclusivamente  a  partir  de
caracteres alfanuméricos, un escenario más restringido, pero no por ello inalcanzable. Una investigación
preliminar,  guiada  por  términos  específicos  como  md5  alphanumeric  collisions,  conduce  rápidamente a
recursos que documentan colisiones de este tipo. Entre ellos destaca una publicación en redes sociales que
afirma  la  existencia  de  una  colisión  MD5  alfanumérica  de  72  bytes,  cuya  validez  puede  verificarse
empíricamente  sin  dificultad.  La  confirmación  de  este  hallazgo  demuestra  que  es  posible  generar  dos
cadenas  alfanuméricas  distintas  que  produzcan  el  mismo  hash  MD5,  cumpliendo  así  las  condiciones
necesarias para explotar la lógica defectuosa del servicio.

Más  aún,  la  disponibilidad  de  herramientas  de  código  abierto  especializadas  permite  generar  colisiones
adicionales con relativa facilidad, ampliando el  conjunto  de candidatos potenciales  y  proporcionando al
atacante un margen operativo suficiente para construir los pares de credenciales necesarios. Estas colisiones
alfanuméricas constituyen, en definitiva, el vector de explotación fundamental del desafío, ya que permiten
registrar dos usuarios distintos cuyos nombres de usuario comparten el mismo hash MD5 y cuya contraseña
es idéntica, satisfaciendo así las condiciones que desencadenan la terminación anómala de la aplicación y
la consiguiente filtración de la flag.

Exploitation

A  estas  alturas,  la  lógica  de  explotación  del  servicio  puede  considerarse  plenamente  delineada.  El
comportamiento defectuoso que conduce a la terminación abrupta de la aplicación exige la existencia de
dos registros construidos por el atacante, cada uno con un nombre de usuario distinto, pero con un hash
MD5  idéntico  y  con  una  contraseña  común.  Esta  configuración  es  imprescindible  para  satisfacer  la
condición  de  autenticación  basada  en  la  comparación  estricta  del  par  [usr_hash,  pwd]  con  los  valores
almacenados en la base de datos.

7 de septiembre de 2026

4

La divergencia entre el nombre de usuario en texto claro suministrado durante el proceso de autenticación
y  el  nombre  de  usuario  almacenado  en  el  registro  que  satisface  dicha  comparación  es,  precisamente,  el
detonante del fallo lógico que culmina en la exposición de la flag.

La elección del usuario con el que se realiza la autenticación no es arbitraria. Debido a la naturaleza de las
estructuras de diccionario en Python, los elementos se recorren en el orden en que fueron insertados. Tras
registrar los dos usuarios colisionados, el primer registro insertado será evaluado en primer lugar durante
el proceso de autenticación.

Dado  que  ambos  usuarios  comparten  el  mismo  hash  MD5  y  la  misma  contraseña,  la  condición  de
coincidencia se cumplirá para el primer registro, independientemente de cuál sea el usuario con el que se
intenta  iniciar  sesión.  Sin  embargo,  como  los  nombres  de  usuario  en  texto  claro  difieren,  la  aplicación
detectará  la  inconsistencia  y  ejecutará  la  ruta  defectuosa  que  provoca  su  terminación  y  la  consiguiente
filtración de la flag.

En este punto, la base de datos contendrá dos entradas con nombres de usuario distintos, pero con digestos
MD5 idénticos, generados a partir de una colisión alfanumérica previamente identificada. La contraseña
compartida garantiza que el par [usr_hash, pwd] coincida con el primer registro durante la autenticación.
La  discrepancia  entre  el  nombre  de  usuario  proporcionado  y  el  almacenado  en  dicho  registro  activa  el
comportamiento anómalo del servicio. Este diseño permite al atacante reproducir de manera determinista
la condición de fallo y obtener la flag sin necesidad de manipular otros componentes del sistema.

Una vez comprendida esta dinámica, resulta trivial encapsular el proceso en una función que automatice
los  pasos  necesarios:  registrar  el  primer  usuario  colisionado  con  una  contraseña  arbitraria,  registrar  el
segundo  usuario  colisionado  con  la  misma  contraseña  y,  finalmente,  autenticarse  utilizando  el  segundo
nombre de usuario para garantizar que la inconsistencia se produzca en el primer registro evaluado. Esta
secuencia reproduce fielmente el vector de explotación y permite obtener la flag de manera sistemática.

7 de septiembre de 2026

5

7 de septiembre de 2026

6


