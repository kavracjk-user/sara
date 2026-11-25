# Diseño de la interfaz del analista — estilo B «expediente forense»

Referencia visual para construir `frontend/`. Los archivos `.dc.html` son el boceto
aprobado por el autor (25-nov-2026): HTML con una sintaxis de plantilla del editor de diseño
(`{{campo}}`, `<sc-for>`, `<sc-if>`). **No son código de producción**: sirven para leer
estructura, textos, medidas y estilos en línea. Los datos que muestran son **ilustrativos**
(casos C-0002 a C-0007, horas y direcciones de ejemplo); no son resultados de la evaluación.

| Archivo | Pantalla (Tabla 4.18 del perfil) |
|---|---|
| `01-lista-de-casos.dc.html` | Lista de casos: caso, tipo de alerta, activo, prioridad sugerida y estado de revisión |
| `02-expediente.dc.html` | Expediente del caso y registro de decisión |
| `03-exportacion.dc.html` | Exportación para la evaluación (RF-14) |

## Concepto
Cada caso es un expediente archivado. La «procedencia» del perfil se muestra como cadena de
custodia: cada evidencia indica el campo de origen y la hora en que se obtuvo (RNF-05).
SARA sugiere; el analista decide (RNF-06). SARA no ejecuta acciones sobre equipos (RNF-01).

## Tokens
| Uso | Valor |
|---|---|
| Fondo (papel de mesa) | `#F2ECDF` |
| Hoja del documento | `#FBF8F1` |
| Hoja del formulario | `#FFFDF8` |
| Pestaña / carpeta manila | `#E4D9BC` |
| Tinta | `#1C1A17` |
| Texto secundario | `#5E574B` |
| Líneas | `#CFC6B2` (finas), `#B9AE96` (bordes), `#1C1A17` (gruesas) |
| Rojo de sello (único acento) | `#B3261E` |
| Títulos | Fraunces 600/700 |
| Texto | IBM Plex Sans 400/500/600 |
| Datos, ids, campos | IBM Plex Mono 400/500 |

## Reglas de diseño
- Un solo color de acento (rojo de sello). La prioridad no depende solo del color: siempre va con texto.
- Prioridad: **Alta** = sello rojo girado con doble borde; **Media** = borde de tinta; **Baja** = borde fino gris;
  **Información insuficiente** = borde discontinuo. Nunca se muestra «Baja» cuando faltan datos.
- Un dato que falta se escribe «Dato no disponible» en cursiva; nunca vacío ni inventado.
- Los estados de un paso son cuatro y distintos: con resultado, sin resultado, fallido, no aplicable.
- La decisión exige elegir qué se decide y una justificación no vacía (RF-11). Al registrar aparece el sello «REGISTRADO».
- Matriz de criterios (Tabla 3.5): filas = nivel de la alerta (Alto, Medio, Bajo); columnas = importancia del activo
  (Alta, Media, Baja, No catalogado); la celda del caso va rodeada en rojo. Los umbrales de nivel están pendientes del tutor.
- Contraste mínimo 4.5:1 en texto; controles de al menos 44 px; etiquetas reales en cada campo.
