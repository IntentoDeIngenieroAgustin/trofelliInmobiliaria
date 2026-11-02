// Utilidades de seguridad, sanitización XSS, validación por lista blanca y rate-limiting para formularios

const DANGEROUS_PATTERNS = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /<\/?[a-z][^>]*>/gi, // Etiquetas HTML (<svg>, <img>, <iframe>, <object>, etc.)
  /javascript\s*:/gi,
  /vbscript\s*:/gi,
  /data\s*:[^,\s]*/gi,
  /on[a-z]+\s*=/gi, // Manejadores de eventos inline (onerror=, onload=, onclick=, etc.)
  /expression\s*\(/gi,
  /url\s*\(\s*['"]?\s*javascript:/gi,
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, // Caracteres de control ASCII
  /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g // Caracteres invisibles y de control bidireccional (anti-spoofing)
];

const HTML_ENTITIES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;'
});

/**
 * Escapa caracteres especiales HTML para prevenir inyección DOM / XSS reflejado.
 */
export function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"'/`]/g, (char) => HTML_ENTITIES[char] || char);
}

/**
 * Detecta si una cadena contiene vectores de ataque XSS o inyección de código.
 */
export function containsXSSPayload(value) {
  if (typeof value !== 'string' || !value) return false;
  const normalized = value.normalize('NFKC');
  return (
    /<[a-z!/][\s\S]*>/i.test(normalized) ||
    /(?:javascript|vbscript|data)\s*:/i.test(normalized) ||
    /\bon[a-z]{2,}\s*=/i.test(normalized) ||
    /(?:alert|confirm|prompt|eval|Function)\s*\(/i.test(normalized) ||
    /(?:document\.|window\.|localStorage|sessionStorage|cookie)/i.test(normalized)
  );
}

/**
 * Limpia y normaliza texto de entrada en tiempo real o antes de enviar.
 * - Normaliza Unicode (NFKC) para evitar bypass con caracteres de ancho completo.
 * - Elimina etiquetas HTML, atributos de eventos, esquemas peligrosos y caracteres invisibles.
 * - Elimina caracteres angulares o de inyección residuales.
 */
export function sanitizeInput(value, { maxLength = 200, allowNewlines = false, trimEdges = false } = {}) {
  if (typeof value !== 'string') return '';

  let clean = value.normalize('NFKC');

  for (const pattern of DANGEROUS_PATTERNS) {
    clean = clean.replace(pattern, '');
  }

  // Remueve caracteres de apertura/cierre de etiquetas o backticks para blindar texto plano
  clean = clean.replace(/[<>`\\]/g, '');

  if (allowNewlines) {
    clean = clean.replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n');
    clean = clean.replace(/[^\S\n]+/g, ' ');
  } else {
    clean = clean.replace(/\s+/g, ' ');
  }

  if (trimEdges) {
    clean = clean.trim();
  }

  return clean.slice(0, maxLength);
}

/**
 * Listas blancas (Allowlists) inmutables para campos cerrados del formulario inmobiliario.
 */
export const FORM_OPTIONS = Object.freeze({
  tiposVivienda: Object.freeze([
    'Departamento',
    'Emprendimiento en Pozo',
    'Casa',
    'Dúplex / PH',
    'Terreno / Lote',
    'Local / Oficina'
  ]),
  operaciones: Object.freeze([
    'Compra / Vivienda propia',
    'Inversión / Pozo',
    'Alquiler',
    'Vender / Tasar mi propiedad'
  ]),
  presupuestos: Object.freeze([
    'Hasta USD 60.000',
    'USD 60.000 – USD 120.000',
    'USD 120.000 – USD 200.000',
    'USD 200.000 – USD 350.000',
    'Más de USD 350.000',
    'Alquiler hasta $ 600.000 / mes',
    'Alquiler más de $ 600.000 / mes',
    'A definir / Busco asesoramiento'
  ]),
  ambientes: Object.freeze([
    'Monoambiente',
    '1 Dormitorio',
    '2 Dormitorios',
    '3 o más Dormitorios',
    'Indistinto'
  ]),
  zonas: Object.freeze([
    'Costanera',
    'Centro / Microcentro',
    'Zona Residencial',
    'Barrio Cerrado / Periferia',
    'Indistinto / Abierto a propuestas'
  ]),
  financiacion: Object.freeze([
    'Contado',
    'Anticipo + Cuotas (Pozo)',
    'Crédito Hipotecario',
    'Entrega propiedad en parte de pago',
    'Alquiler tradicional',
    'A conversar'
  ])
});

const NAME_REGEX = /^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ' -]{2,80}$/;
const PHONE_REGEX = /^[0-9+\s()-]{7,25}$/;
const EMAIL_REGEX = /^[^\s@<>'"`]+@[^\s@<>'"`]+\.[a-zA-Z]{2,12}$/;

/**
 * Valida todos los campos del formulario inmobiliario contra reglas estrictas y listas blancas.
 */
export function validateRealEstateForm(rawForm) {
  const errors = {};

  // Verificar si algún campo contiene intento explícito de XSS
  for (const [key, val] of Object.entries(rawForm)) {
    if (typeof val === 'string' && containsXSSPayload(val)) {
      errors.security = 'Se detectaron caracteres o etiquetas no permitidas por el filtro de seguridad XSS.';
      errors[key] = 'Contenido bloqueado por seguridad.';
    }
  }

  const nombre = sanitizeInput(rawForm.nombre, { maxLength: 80, trimEdges: true });
  const telefono = sanitizeInput(rawForm.telefono, { maxLength: 25, trimEdges: true });
  const email = sanitizeInput(rawForm.email, { maxLength: 120, trimEdges: true });
  const tipoVivienda = sanitizeInput(rawForm.tipoVivienda, { maxLength: 60, trimEdges: true });
  const operacion = sanitizeInput(rawForm.operacion, { maxLength: 60, trimEdges: true });
  const presupuesto = sanitizeInput(rawForm.presupuesto, { maxLength: 80, trimEdges: true });
  const ambientes = sanitizeInput(rawForm.ambientes, { maxLength: 40, trimEdges: true });
  const zona = sanitizeInput(rawForm.zona, { maxLength: 60, trimEdges: true });
  const financiacion = sanitizeInput(rawForm.financiacion, { maxLength: 60, trimEdges: true });
  const mensaje = sanitizeInput(rawForm.mensaje, { maxLength: 450, allowNewlines: true, trimEdges: true });

  // 1. Nombre y Apellido
  if (!nombre || nombre.length < 2) {
    errors.nombre = 'Ingresá tu nombre y apellido (mínimo 2 caracteres).';
  } else if (!NAME_REGEX.test(nombre)) {
    errors.nombre = 'El nombre solo puede contener letras y espacios.';
  }

  // 2. Teléfono / WhatsApp
  const digitsOnly = telefono.replace(/\D/g, '');
  if (!telefono) {
    errors.telefono = 'Ingresá un teléfono de contacto.';
  } else if (!PHONE_REGEX.test(telefono) || digitsOnly.length < 7 || digitsOnly.length > 15) {
    errors.telefono = 'Ingresá un número válido (entre 7 y 15 dígitos, ej: 3794 000000).';
  }

  // 3. Email (Opcional, pero si se completa se valida estrictamente)
  if (email && !EMAIL_REGEX.test(email)) {
    errors.email = 'El formato del correo electrónico no es válido.';
  }

  // 4. Validación estricta por lista blanca (Allowlist)
  if (!FORM_OPTIONS.tiposVivienda.includes(tipoVivienda)) {
    errors.tipoVivienda = 'Seleccioná un tipo de propiedad válido.';
  }
  if (!FORM_OPTIONS.operaciones.includes(operacion)) {
    errors.operacion = 'Seleccioná un tipo de operación válido.';
  }
  if (!FORM_OPTIONS.presupuestos.includes(presupuesto)) {
    errors.presupuesto = 'Seleccioná un rango de presupuesto válido.';
  }
  if (!FORM_OPTIONS.ambientes.includes(ambientes)) {
    errors.ambientes = 'Seleccioná la cantidad de ambientes.';
  }
  if (!FORM_OPTIONS.zonas.includes(zona)) {
    errors.zona = 'Seleccioná una zona de preferencia válida.';
  }
  if (!FORM_OPTIONS.financiacion.includes(financiacion)) {
    errors.financiacion = 'Seleccioná una modalidad válida.';
  }

  // 5. Mensaje opcional
  if (mensaje.length > 450) {
    errors.mensaje = 'El mensaje no puede superar los 450 caracteres.';
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
    sanitizedData: {
      nombre,
      telefono,
      email,
      tipoVivienda,
      operacion,
      presupuesto,
      ambientes,
      zona,
      financiacion,
      mensaje
    }
  };
}

/**
 * Control de frecuencia (Rate Limiting) en cliente para evitar envíos automatizados o spam.
 */
const RATE_LIMIT_KEY = 'trofelli_contact_rl';
const COOLDOWN_MS = 12000; // 12 segundos entre envíos
const MAX_ATTEMPTS_WINDOW = 5; // Máximo 5 envíos cada 10 minutos
const WINDOW_MS = 10 * 60 * 1000;

export function checkRateLimit() {
  const now = Date.now();
  try {
    const raw = sessionStorage.getItem(RATE_LIMIT_KEY);
    const history = raw ? JSON.parse(raw) : [];
    const recent = Array.isArray(history) ? history.filter((ts) => typeof ts === 'number' && now - ts < WINDOW_MS) : [];

    if (recent.length > 0 && now - recent[recent.length - 1] < COOLDOWN_MS) {
      const waitSec = Math.ceil((COOLDOWN_MS - (now - recent[recent.length - 1])) / 1000);
      return {
        allowed: false,
        reason: `Por seguridad, aguardá ${waitSec} segundos antes de volver a enviar.`
      };
    }

    if (recent.length >= MAX_ATTEMPTS_WINDOW) {
      return {
        allowed: false,
        reason: 'Alcanzaste el límite temporal de envíos. Intentá nuevamente en unos minutos.'
      };
    }

    return { allowed: true };
  } catch {
    return { allowed: true };
  }
}

export function recordSubmissionAttempt() {
  const now = Date.now();
  try {
    const raw = sessionStorage.getItem(RATE_LIMIT_KEY);
    const history = raw ? JSON.parse(raw) : [];
    const recent = Array.isArray(history) ? history.filter((ts) => typeof ts === 'number' && now - ts < WINDOW_MS) : [];
    recent.push(now);
    sessionStorage.setItem(RATE_LIMIT_KEY, JSON.stringify(recent));
  } catch {
    // Ignorar si sessionStorage está restringido
  }
}

/**
 * Construye el mensaje prepersonalizado y genera una URL segura hacia la API oficial de WhatsApp.
 */
export function buildWhatsAppMessage(sanitizedData) {
  const lines = [
    'Hola *Trofelli Propiedades*, les escribo desde la web para realizar una consulta inmobiliaria:',
    '',
    `• *Nombre:* ${sanitizedData.nombre}`,
    `• *Teléfono:* ${sanitizedData.telefono}`,
    sanitizedData.email ? `• *Email:* ${sanitizedData.email}` : null,
    `• *Operación:* ${sanitizedData.operacion}`,
    `• *Tipo de propiedad:* ${sanitizedData.tipoVivienda}`,
    `• *Presupuesto estimado:* ${sanitizedData.presupuesto}`,
    `• *Ambientes / Dormitorios:* ${sanitizedData.ambientes}`,
    `• *Zona de interés:* ${sanitizedData.zona}`,
    `• *Modalidad / Pago:* ${sanitizedData.financiacion}`,
    sanitizedData.mensaje ? `\n*Comentarios adicionales:*\n${sanitizedData.mensaje}` : null
  ].filter(Boolean);

  return lines.join('\n');
}

export function buildSafeWhatsAppUrl(phoneNumber, sanitizedData) {
  const cleanPhone = String(phoneNumber || '').replace(/\D/g, '');
  if (!/^\d{10,15}$/.test(cleanPhone)) {
    throw new Error('Número de WhatsApp de destino inválido.');
  }

  const message = buildWhatsAppMessage(sanitizedData);
  const encodedText = encodeURIComponent(message);
  return `https://wa.me/${cleanPhone}?text=${encodedText}`;
}

