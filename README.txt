Take no Kamu - Plataforma de Encuestas para el restaurante

Versión: 1.0

Take no Kamu es un restaurante con una plataforma web diseñada para recopilar encuestas de satisfacción de clientes, ofreciendo a los usuarios cupones de descuento como incentivo por su participación. El sistema permite a los restaurantes visualizar gráficos de resultados por sucursal o país, gestionar usuarios y sucursales, y mantener un registro seguro de los eventos críticos del sistema.

1. Descripción

El objetivo principal de Take no Kamu es mejorar la experiencia del cliente en restaurantes mediante el análisis de encuestas en línea. Entre sus funcionalidades destacan:

Registro y login de usuarios con verificación vía correo.

Acceso a encuestas por sucursal.

Generación automática de cupones de descuento entre el 35% y el 40%.

Visualización de gráficos de resultados con filtros por fecha y sucursal.

Seguridad robusta con contraseñas hasheadas, protección contra fuerza bruta y registros de eventos.


2. Tecnologías utilizadas:

Flask como framework backend.

MySQL como sistema gestor de base de datos con InnoDB.

Pandas y Matplotlib para el análisis de datos y generación de gráficos.

dotenv para la configuración de variables de entorno.

smtplib para envío de correos electrónicos con cupones y códigos de verificación.


3. Limitaciones:

Requiere conexión a internet para su funcionamiento.

No posee app móvil nativa (diseño responsivo solamente).

Los códigos de verificación tienen vencimiento limitado (30 min).


4. Requisitos

Python 3.10 o superior

MySQL Server (local o remoto)

pip y venv para entorno virtual

Librerías Python: Descritas en el archivo requirements.txt

5. Tecnologías utilizadas
Flask – Microframework de Python para el desarrollo web backend.

MySQL – Sistema de gestión de bases de datos relacional.

Pandas – Librería para análisis de datos en Python.

Matplotlib – Librería para generación de gráficos.

python-dotenv – Para cargar variables de entorno desde un archivo .env.

smtplib – Módulo para envío de correos electrónicos.

Werkzeug Security – Utilidades para manejo seguro de contraseñas.


6. Instalación
Para instalar y configurar el proyecto en tu entorno local, sigue el siguiente enlace a nuestro repositorio de GitHub, donde encontrarás lo necesario para poder realizar la instalación

https://github.com/takenokamu/Encuesta-Satisfaccion-


7. Uso
Rutas principales:

/login: Inicio de sesión de usuarios.

/registro: Registro de nuevos usuarios con verificación por correo.

/encuesta: Encuesta de satisfacción por sucursal.

/generar_cupon: Genera un cupón si se completó una encuesta.

/admin/dashboard: Panel de administración con filtros y gráficos.

Seguridad implementada:

Protección de rutas con @login_required.

Hash de contraseñas usando werkzeug.security.

Límite de intentos de login con session['intentos_fallidos'].

Logging de eventos en registro_seguridad.log.


8. Preguntas Frecuentes (FAQ)
8.1. ¿Necesito estar conectado a internet para usar la aplicación?
Sí, es necesario contar con conexión a internet para registrarte, iniciar sesión, completar la encuesta y recibir el cupón.
8.2. ¿Puedo usar la aplicación desde mi celular?
Sí, la aplicación es compatible con navegadores modernos en dispositivos móviles Android e iOS, así como en computadoras.
8.3. ¿Qué hago si no recibí el código de verificación por correo?
Verifica tu carpeta de spam o correo no deseado. Si aún no lo recibes, puedes pulsar el enlace “¿No recibiste el código? Reenviar código” en la pantalla de verificación.
8.4. ¿Cuánto tiempo tengo para ingresar el código de verificación?
El código tiene una validez de 15 minutos desde que fue enviado. Después de ese tiempo, deberás solicitar uno nuevo.
8.5. ¿Qué tan segura debe ser mi contraseña?
Tu contraseña debe tener al menos 8 caracteres. Se recomienda incluir una combinación de letras mayúsculas, números y símbolos para mayor seguridad. El medidor de fuerza te ayudará a saber qué tan segura es mientras la escribes.
8.6. ¿Puedo hacer la encuesta más de una vez?
Por el momento cada usuario puede participar una sola vez cada 30 días para asegurar resultados auténticos y válidos.
8.7. ¿Qué tipo de recompensa recibiré después de completar la encuesta?
Recibirás un cupón digital con un porcentaje de descuento aleatorio entre 35% y 40%, válido para tu próxima visita.
8.8. ¿El cupón tiene fecha de vencimiento?
Sí, tienen una vigencia de 30 días.
8.9. ¿Cómo protegen mi información personal?
Tus datos están protegidos mediante protocolos de seguridad estándar y solo se utilizan para fines de verificación y entrega del cupón.


9. Créditos y agradecimientos

Backend & Base de Datos: Adrián Emmanuel Allard Hernández

Frontend: Carlos Gael Gutiérrez Flores

Diseño: Arantza Sánchez Ramírez

Coordinación & Documentación: Emanuel Herrera Briseño

Agradecimientos especiales a los docentes por su guía en el desarrollo del sistema.


10. Licencia

Este proyecto es de uso académico y no tiene fines comerciales. Se prohíbe la distribución del código sin autorización de los autores.