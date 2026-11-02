# Trofelli · Revista de propiedades
Última versión: diseño oscuro inspirado en la referencia arquitectónica.

React + Vite + JavaScript + Tailwind CSS v4. Sin backend.

## Ejecutar
Instalá Node.js 22 LTS o posterior compatible. Abrí una terminal en esta carpeta:

```bash
npm ci
npm run dev
```

Abrí la dirección que muestre Vite. No abras index.html directamente.

## Producción
```bash
npm run build
```
El resultado está en dist/ y se puede desplegar en un hosting estático.

## Archivos
- frontend/src/App.jsx: página, fichas y editor de propiedades.
- frontend/src/index.css: diseño y adaptación móvil.
- frontend/src/components/layout/Navbar.jsx: navbar píldora.
- frontend/src/data/properties.js: propiedades iniciales de ejemplo.
- frontend/src/store/useProperties.js: persistencia local.
- frontend/public/images/: fotografías incluidas.

## Funciones
Filtros de operación, tipo y búsqueda; favoritos; alta, edición, ocultación y eliminación de propiedades; carga de imágenes; elección de imagen de portada.
Los cambios y favoritos se guardan solo en el navegador mediante localStorage. El panel es una demo sin autenticación, no un administrador seguro de producción.

Las propiedades, precios y fotos son ilustrativos. Las fotos proceden de Unsplash. Las tipografías se cargan desde Google Fonts y tienen fuentes alternativas.
