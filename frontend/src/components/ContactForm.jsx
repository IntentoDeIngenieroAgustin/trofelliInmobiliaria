import { useState, useRef, useEffect } from 'react';
import { ShieldCheck, MessageCircle, AlertTriangle, Check } from 'lucide-react';
import {
  FORM_OPTIONS,
  sanitizeInput,
  containsXSSPayload,
  validateRealEstateForm,
  checkRateLimit,
  recordSubmissionAttempt,
  buildWhatsAppMessage,
  buildSafeWhatsAppUrl
} from '../utils/security';

// Número de WhatsApp comercial (formato internacional sin '+' ni espacios, ej: Corrientes +54 9 379 4424000)
const WHATSAPP_NUMBER = import.meta.env.VITE_WHATSAPP_NUMBER || '5493794424000';

const INITIAL_STATE = {
  tipoVivienda: 'Departamento',
  operacion: 'Compra / Vivienda propia',
  presupuesto: 'USD 60.000 – USD 120.000',
  ambientes: '2 Dormitorios',
  zona: 'Costanera',
  financiacion: 'Contado',
  nombre: '',
  telefono: '',
  email: '',
  mensaje: '',
  // Honeypot anti-bots (debe permanecer vacío)
  empresa_web: ''
};

export default function ContactForm({ onNotify, prefill }) {
  const [form, setForm] = useState(INITIAL_STATE);
  const [errors, setErrors] = useState({});
  const [xssAlert, setXssAlert] = useState('');
  const [showPreview, setShowPreview] = useState(false);
  const mountTimeRef = useRef(Date.now());

  useEffect(() => {
    if (!prefill) return;
    setForm((prev) => {
      const mappedType = FORM_OPTIONS.tiposVivienda.includes(prefill.type)
        ? prefill.type
        : prev.tipoVivienda;
      const mappedOp =
        prefill.operation === 'Alquiler'
          ? 'Alquiler'
          : 'Compra / Vivienda propia';
      const safeTitle = sanitizeInput(prefill.title || '', { maxLength: 100, trimEdges: true });
      const safePrice = sanitizeInput(prefill.price || '', { maxLength: 50, trimEdges: true });
      return {
        ...prev,
        tipoVivienda: mappedType,
        operacion: mappedOp,
        mensaje: safeTitle
          ? `Me interesa recibir información sobre la propiedad "${safeTitle}" (${safePrice}).`
          : prev.mensaje
      };
    });
  }, [prefill]);

  const handleFieldChange = (field, rawValue, options = {}) => {
    if (typeof rawValue === 'string' && containsXSSPayload(rawValue)) {
      setXssAlert('Filtro XSS activo: se bloquearon etiquetas HTML o scripts no permitidos.');
    } else if (xssAlert) {
      setXssAlert('');
    }

    const cleanValue = sanitizeInput(rawValue, {
      maxLength: options.maxLength || 120,
      allowNewlines: Boolean(options.allowNewlines),
      trimEdges: false
    });

    setForm((prev) => ({ ...prev, [field]: cleanValue }));

    if (errors[field] || errors.form) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        delete next.form;
        return next;
      });
    }
  };

  const handleSelectOption = (field, value, allowlist) => {
    if (!allowlist.includes(value)) return;
    setForm((prev) => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    // 1. Verificación Honeypot (Anti-Bots)
    if (form.empresa_web && form.empresa_web.trim() !== '') {
      return;
    }

    // 2. Verificación de tiempo mínimo de interacción (Anti-Bot Time Trap: 1.5s)
    if (Date.now() - mountTimeRef.current < 1500) {
      setErrors({ form: 'Envío demasiado rápido. Por favor revisá tus datos e intentá nuevamente.' });
      return;
    }

    // 3. Control de frecuencia (Rate Limiting en cliente)
    const rateCheck = checkRateLimit();
    if (!rateCheck.allowed) {
      setErrors({ form: rateCheck.reason });
      return;
    }

    // 4. Validación estricta y sanitización XSS
    const validation = validateRealEstateForm(form);
    if (!validation.isValid) {
      setErrors(validation.errors);
      return;
    }

    try {
      const whatsappUrl = buildSafeWhatsAppUrl(WHATSAPP_NUMBER, validation.sanitizedData);
      recordSubmissionAttempt();
      setErrors({});
      setXssAlert('');

      if (onNotify) {
        onNotify('Redirigiendo a WhatsApp con tu consulta personalizada…');
      }

      // Apertura segura previniendo Reverse Tabnabbing (noopener, noreferrer)
      const newWin = window.open(whatsappUrl, '_blank', 'noopener,noreferrer');
      if (newWin) {
        newWin.opener = null;
      }
    } catch (err) {
      setErrors({ form: err.message || 'No se pudo generar el enlace seguro de WhatsApp.' });
    }
  };

  const previewText = buildWhatsAppMessage({
    nombre: sanitizeInput(form.nombre, { maxLength: 80, trimEdges: true }) || '[Tu nombre]',
    telefono: sanitizeInput(form.telefono, { maxLength: 25, trimEdges: true }) || '[Tu teléfono]',
    email: sanitizeInput(form.email, { maxLength: 120, trimEdges: true }),
    tipoVivienda: form.tipoVivienda,
    operacion: form.operacion,
    presupuesto: form.presupuesto,
    ambientes: form.ambientes,
    zona: form.zona,
    financiacion: form.financiacion,
    mensaje: sanitizeInput(form.mensaje, { maxLength: 450, allowNewlines: true, trimEdges: true })
  });

  return (
    <div className="contact-container">
      <div className="contact-header">
        <span className="eyebrow">EL PRÓXIMO CAPÍTULO</span>
        <h2>
          ¿Lo encontramos <em>juntos?</em>
        </h2>
        <p className="contact-subtitle">
          Contanos qué tipo de propiedad o inversión estás buscando. Prepararemos un mensaje personalizado para
          atenderte directamente por WhatsApp.
        </p>
      </div>

      <form className="real-estate-form" onSubmit={handleSubmit} noValidate autoComplete="on">
        {/* Campo Honeypot invisible para bots */}
        <div className="hp-trap" aria-hidden="true">
          <label htmlFor="empresa_web">Sitio web corporativo (no completar)</label>
          <input
            id="empresa_web"
            name="empresa_web"
            type="text"
            tabIndex={-1}
            autoComplete="off"
            value={form.empresa_web}
            onChange={(e) => setForm((prev) => ({ ...prev, empresa_web: e.target.value }))}
          />
        </div>

        {/* Paso 1: Tipo de vivienda / propiedad */}
        <div className="form-block">
          <div className="form-block-head">
            <span className="step-num">01</span>
            <span className="step-label">¿QUÉ TIPO DE PROPIEDAD BUSCÁS?</span>
          </div>
          <div className="pill-selector" role="radiogroup" aria-label="Tipo de propiedad">
            {FORM_OPTIONS.tiposVivienda.map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={form.tipoVivienda === option}
                className={`choice-pill ${form.tipoVivienda === option ? 'selected' : ''}`}
                onClick={() => handleSelectOption('tipoVivienda', option, FORM_OPTIONS.tiposVivienda)}
              >
                {form.tipoVivienda === option && <Check size={13} />}
                {option}
              </button>
            ))}
          </div>
          {errors.tipoVivienda && <span className="field-error">{errors.tipoVivienda}</span>}
        </div>

        {/* Paso 2: Operación, Presupuesto, Ambientes, Zona y Financiación */}
        <div className="form-block">
          <div className="form-block-head">
            <span className="step-num">02</span>
            <span className="step-label">PREFERENCIAS Y PRESUPUESTO</span>
          </div>

          <div className="form-grid-3">
            <label className="form-field">
              <span>Operación</span>
              <select
                value={form.operacion}
                onChange={(e) => handleSelectOption('operacion', e.target.value, FORM_OPTIONS.operaciones)}
              >
                {FORM_OPTIONS.operaciones.map((op) => (
                  <option key={op} value={op}>
                    {op}
                  </option>
                ))}
              </select>
              {errors.operacion && <small className="field-error">{errors.operacion}</small>}
            </label>

            <label className="form-field">
              <span>Rango de presupuesto</span>
              <select
                value={form.presupuesto}
                onChange={(e) => handleSelectOption('presupuesto', e.target.value, FORM_OPTIONS.presupuestos)}
              >
                {FORM_OPTIONS.presupuestos.map((pres) => (
                  <option key={pres} value={pres}>
                    {pres}
                  </option>
                ))}
              </select>
              {errors.presupuesto && <small className="field-error">{errors.presupuesto}</small>}
            </label>

            <label className="form-field">
              <span>Ambientes / Dormitorios</span>
              <select
                value={form.ambientes}
                onChange={(e) => handleSelectOption('ambientes', e.target.value, FORM_OPTIONS.ambientes)}
              >
                {FORM_OPTIONS.ambientes.map((amb) => (
                  <option key={amb} value={amb}>
                    {amb}
                  </option>
                ))}
              </select>
              {errors.ambientes && <small className="field-error">{errors.ambientes}</small>}
            </label>
          </div>

          <div className="form-grid-2">
            <label className="form-field">
              <span>Zona de preferencia en Corrientes</span>
              <select
                value={form.zona}
                onChange={(e) => handleSelectOption('zona', e.target.value, FORM_OPTIONS.zonas)}
              >
                {FORM_OPTIONS.zonas.map((z) => (
                  <option key={z} value={z}>
                    {z}
                  </option>
                ))}
              </select>
              {errors.zona && <small className="field-error">{errors.zona}</small>}
            </label>

            <label className="form-field">
              <span>Forma de pago / Financiación</span>
              <select
                value={form.financiacion}
                onChange={(e) => handleSelectOption('financiacion', e.target.value, FORM_OPTIONS.financiacion)}
              >
                {FORM_OPTIONS.financiacion.map((fin) => (
                  <option key={fin} value={fin}>
                    {fin}
                  </option>
                ))}
              </select>
              {errors.financiacion && <small className="field-error">{errors.financiacion}</small>}
            </label>
          </div>
        </div>

        {/* Paso 3: Datos de contacto y mensaje */}
        <div className="form-block">
          <div className="form-block-head">
            <span className="step-num">03</span>
            <span className="step-label">TUS DATOS DE CONTACTO</span>
          </div>

          <div className="form-grid-3">
            <label className="form-field">
              <span>Nombre y apellido *</span>
              <input
                type="text"
                name="nombre"
                required
                maxLength={80}
                autoComplete="name"
                placeholder="Ej. Martín Gómez"
                value={form.nombre}
                onChange={(e) => handleFieldChange('nombre', e.target.value, { maxLength: 80 })}
                aria-invalid={Boolean(errors.nombre)}
              />
              {errors.nombre && <small className="field-error">{errors.nombre}</small>}
            </label>

            <label className="form-field">
              <span>Teléfono / WhatsApp *</span>
              <input
                type="tel"
                name="telefono"
                required
                maxLength={25}
                inputMode="tel"
                autoComplete="tel"
                placeholder="Ej. +54 9 379 400-0000"
                value={form.telefono}
                onChange={(e) => handleFieldChange('telefono', e.target.value, { maxLength: 25 })}
                aria-invalid={Boolean(errors.telefono)}
              />
              {errors.telefono && <small className="field-error">{errors.telefono}</small>}
            </label>

            <label className="form-field">
              <span>Correo electrónico (opcional)</span>
              <input
                type="email"
                name="email"
                maxLength={120}
                autoComplete="email"
                placeholder="nombre@correo.com"
                value={form.email}
                onChange={(e) => handleFieldChange('email', e.target.value, { maxLength: 120 })}
                aria-invalid={Boolean(errors.email)}
              />
              {errors.email && <small className="field-error">{errors.email}</small>}
            </label>
          </div>

          <label className="form-field full-field">
            <div className="field-label-row">
              <span>Comentarios o detalles adicionales (opcional)</span>
              <small>{form.mensaje.length}/450</small>
            </div>
            <textarea
              name="mensaje"
              rows={3}
              maxLength={450}
              placeholder="Contanos si buscás balcón, cochera, entrega en pozo, fecha estimada de mudanza o si tenés una propiedad para tasar…"
              value={form.mensaje}
              onChange={(e) =>
                handleFieldChange('mensaje', e.target.value, { maxLength: 450, allowNewlines: true })
              }
            />
            {errors.mensaje && <small className="field-error">{errors.mensaje}</small>}
          </label>
        </div>

        {/* Avisos de seguridad XSS o errores de validación */}
        {xssAlert && (
          <div className="security-alert" role="status">
            <AlertTriangle size={16} />
            <span>{xssAlert}</span>
          </div>
        )}

        {(errors.form || errors.security) && (
          <div className="security-alert error-banner" role="alert">
            <AlertTriangle size={16} />
            <span>{errors.form || errors.security}</span>
          </div>
        )}

        {/* Vista previa opcional del mensaje prepersonalizado */}
        <div className="whatsapp-preview-wrapper">
          <button
            type="button"
            className="preview-toggle"
            onClick={() => setShowPreview((v) => !v)}
            aria-expanded={showPreview}
          >
            <MessageCircle size={14} />
            <span>{showPreview ? 'Ocultar vista previa del mensaje' : 'Ver mensaje prepersonalizado para WhatsApp'}</span>
          </button>

          {showPreview && (
            <pre className="whatsapp-preview" aria-label="Vista previa del mensaje de WhatsApp">
              {previewText}
            </pre>
          )}
        </div>

        {/* Acciones y sello de seguridad */}
        <div className="contact-actions">
          <button type="submit" className="wsp-submit-button">
            <span>Enviar consulta por WhatsApp</span>
          </button>

          <a
            className="ig-secondary-button"
            href="https://www.instagram.com/trofelli.propiedades/?hl=es-la"
            target="_blank"
            rel="noopener noreferrer"
          >
            <span>Conversemos por Instagram</span>
          </a>
        </div>

        <div className="security-footnote">
          <ShieldCheck size={14} />
          <span>
            Formulario protegido con sanitización anti-XSS, validación por lista blanca y cifrado directo hacia
            WhatsApp.
          </span>
        </div>
      </form>
    </div>
  );
}
