from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import random
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
import os
from functools import wraps
import hashlib
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Para usar matplotlib en modo no interactivo
import numpy as np
from flask import send_from_directory
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import string
from dotenv import load_dotenv
load_dotenv()  # cargar variables desde .env
from werkzeug.security import generate_password_hash, check_password_hash
import re
import logging
# Importaciones para encriptación
from cryptography.fernet import Fernet, InvalidToken
import base64

# Configura el sistema de logging para registrar eventos en un archivo llamado 'registro_seguridad.log'
# Se establece el nivel de registro como INFO y se define el formato con fecha, nivel y mensaje
logging.basicConfig(filename='registro_seguridad.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define la ruta absoluta a la carpeta 'static/images' para guardar los gráficos generados
STATIC_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
IMAGES_FOLDER = os.path.join(STATIC_FOLDER, 'images')

# Crea la carpeta de imágenes si no existe, para evitar errores al guardar gráficos
os.makedirs(IMAGES_FOLDER, exist_ok=True)

# Nombre del archivo donde se almacenará la clave de cifrado para Fernet
ARCHIVO_CLAVE = "clave.key"

def obtener_o_generar_clave():
    """Genera una clave Fernet si no existe y la guarda en un archivo, o la carga si ya existe."""
    # Si el archivo de clave ya existe, se lee la clave desde el archivo
    if os.path.exists(ARCHIVO_CLAVE):
        with open(ARCHIVO_CLAVE, 'rb') as f:
            clave = f.read()
    else:
        # Si no existe, se genera una nueva clave segura y se guarda en el archivo especificado
        clave = Fernet.generate_key()
        with open(ARCHIVO_CLAVE, 'wb') as f:
            f.write(clave)
        print(f"⚠️ Clave de encriptación generada y guardada en {ARCHIVO_CLAVE}. Guarda este archivo en un lugar seguro.")
    
    # Se retorna la clave (ya sea cargada o recién generada)
    return clave

# Inicializa el cifrador global usando la clave generada o cargada desde archivo
try:
    clave_encriptacion = obtener_o_generar_clave()
    cipher_suite = Fernet(clave_encriptacion)
except Exception as e:
    # Si ocurre un error al generar o cargar la clave, se registra y desactiva la encriptación
    print(f"Error al inicializar encriptación: {e}")
    cipher_suite = None

def encriptar_dato(dato):
    """Encripta un dato sensible usando Fernet y codifica el resultado en base64"""
    if not dato or not cipher_suite:
        return dato  # Si no hay dato o el cifrador no está inicializado, devuelve el dato tal cual
    try:
        dato_encriptado = cipher_suite.encrypt(dato.encode())
        return base64.urlsafe_b64encode(dato_encriptado).decode()
    except Exception as e:
        # Registra cualquier error de encriptación en el log
        logging.error(f"Error al encriptar dato: {e}")
        return dato

def desencriptar_dato(dato_encriptado):
    """Desencripta un dato en base64 que fue cifrado con Fernet"""
    if not dato_encriptado or not cipher_suite:
        return dato_encriptado  # Si no hay dato o no se puede desencriptar, se devuelve igual
    try:
        # Heurística para detectar si el dato parece estar sin encriptar (por ejemplo, un correo)
        if '@' in dato_encriptado and '.' in dato_encriptado:
            return dato_encriptado
        
        dato_base64 = base64.urlsafe_b64decode(dato_encriptado.encode())
        dato_desencriptado = cipher_suite.decrypt(dato_base64)
        return dato_desencriptado.decode()
    except (InvalidToken, Exception) as e:
        # Si ocurre error al desencriptar (clave incorrecta, dato corrupto...), se asume que no está encriptado
        return dato_encriptado

def buscar_usuario_por_correo(correo_plano):
    """
    Busca un usuario por su correo, considerando que puede estar almacenado cifrado.
    Primero intenta comparar con el correo encriptado directamente.
    Si no encuentra, recorre todos los correos y los desencripta uno a uno para comparar.
    """
    cur = mysql.connection.cursor()
    
    # Intentar encontrar el correo en su forma cifrada
    correo_encriptado = encriptar_dato(correo_plano)
    cur.execute("SELECT id_usuario, nombre, verificado, privilegios, contraseña, codigo_verificacion, correo, telefono FROM usuarios WHERE correo = %s", (correo_encriptado,))
    usuario = cur.fetchone()
    
    if usuario:
        cur.close()
        return usuario
    
    # Si no se encontró, recuperar todos los usuarios y desencriptar los correos uno por uno
    cur.execute("SELECT id_usuario, nombre, verificado, privilegios, contraseña, codigo_verificacion, correo, telefono FROM usuarios")
    todos_usuarios = cur.fetchall()
    cur.close()
    
    for usuario_db in todos_usuarios:
        correo_db = desencriptar_dato(usuario_db[6])  # posición 6 corresponde a 'correo'
        if correo_db.lower() == correo_plano.lower():
            return usuario_db

    # Si no se encontró coincidencia, retorna None
    return None

# Inicializa la aplicación Flask
app = Flask(__name__)

# Clave secreta para manejar sesiones y tokens. 
# Se obtiene de variables de entorno por seguridad, con un valor por defecto en caso de que no exista
app.secret_key = os.environ.get('SECRET_KEY', '5mcJAvC298$7')

# Configuración de conexión a MySQL usando variables de entorno.
# Esto permite proteger credenciales sensibles y facilitar despliegue en distintos entornos (desarrollo, producción, etc.)
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'Ericko11$')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'encuestas_db')

# Configuración del correo emisor para el envío de emails (verificación, recuperación, etc.)
EMAIL_SENDER = os.environ.get('EMAIL_SENDER', 'takenokamu@gmail.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'kcdvjijtgcsucvmb')

# Inicializa la extensión MySQL con la configuración anterior
mysql = MySQL(app)


# ----- Funciones auxiliares -----

# Genera códigos de cupón aleatorios alfanuméricos
def generar_codigo_cupon():
    """Genera un código alfanumérico aleatorio de 6 caracteres para cupones"""
    caracteres = string.ascii_uppercase + string.digits  # Letras mayúsculas y números
    return ''.join(random.choice(caracteres) for _ in range(6))

# Enviar cupón por correo
def enviar_cupon(destinatario, codigo, porcentaje):
    """Envía un correo con el cupón de descuento correspondiente"""
    try:
        # Desencripta el correo del destinatario (por seguridad está cifrado en la base de datos)
        correo_desencriptado = desencriptar_dato(destinatario)
        
        # Crea un correo tipo multipart (permite texto + imágenes)
        mensaje = MIMEMultipart()
        mensaje['Subject'] = f'Tu cupón de {porcentaje}% de descuento - Gracias por tu encuesta'
        mensaje['From'] = EMAIL_SENDER
        mensaje['To'] = correo_desencriptado
        
        # Cuerpo del correo como texto
        texto = f'''
        Hola,
        
        ¡Gracias por responder nuestra encuesta de satisfacción!
        
        Como agradecimiento, te enviamos un cupón de {porcentaje}% de descuento para tu próxima visita.
        
        Tu código de cupón es: {codigo}
        
        Este cupón es válido por 30 días a partir de hoy.
        
        ¡Esperamos verte pronto!
        
        Saludos,
        El equipo de Encuestas
        '''
        parte_texto = MIMEText(texto)
        mensaje.attach(parte_texto)

        # Adjunta una imagen del cupón si existe
        ruta_imagen = os.path.join(STATIC_FOLDER, 'images', f'cupon_{porcentaje}.png')
        if os.path.exists(ruta_imagen):
            with open(ruta_imagen, 'rb') as img:
                imagen = MIMEImage(img.read())
                imagen.add_header('Content-ID', '<cupon>')  # Para uso inline
                imagen.add_header('Content-Disposition', 'inline', filename=f'cupon_{porcentaje}.png')
                mensaje.attach(imagen)

        # Envía el correo usando conexión segura (SSL) con el servidor SMTP de Gmail
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(mensaje)
        return True

    except Exception as e:
        # Si ocurre un error en el proceso, lo imprime y devuelve False
        print(f"Error al enviar email con cupón: {e}")
        return False

# Genera un hash seguro a partir de una contraseña plana
def hash_password(password):
    return generate_password_hash(password)

# Genera un código numérico aleatorio de 6 dígitos para verificación (por ejemplo, para activar una cuenta)
def generar_codigo_verificacion():
    """Genera un código de verificación de 6 dígitos"""
    return str(random.randint(100000, 999999))

# Envía un correo electrónico con el código de verificación
def enviar_codigo_verificacion(destinatario, codigo):
    """Envía un correo con el código de verificación"""
    try:
        # Desencripta el correo del destinatario (si está almacenado cifrado en la base de datos)
        correo_desencriptado = desencriptar_dato(destinatario)
        
        # Crea el mensaje de verificación
        mensaje = EmailMessage()
        mensaje['Subject'] = 'Tu código de verificación - Encuesta de Satisfacción'
        mensaje['From'] = EMAIL_SENDER
        mensaje['To'] = correo_desencriptado
        mensaje.set_content(f'''
        Hola,
        
        Gracias por registrarte en nuestro sistema de encuestas de satisfacción.
        
        Tu código de verificación es: {codigo}
        
        Si no solicitaste este código, puedes ignorar este correo.
        
        Saludos,
        El equipo de Encuestas
        ''')

        # Conexión segura con servidor SMTP y envío del correo
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(mensaje)
        
        # Registro de éxito en log
        logging.info(f"Código de verificación enviado al correo: {correo_desencriptado}")
        return True

    except Exception as e:
        # Registro de error en log
        logging.error(f"Error al enviar email de verificación: {e}")
        return False

# Decorador que restringe el acceso a rutas que requieren que el usuario haya iniciado sesión
def login_required(f):
    """Decorador para proteger rutas que requieren autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Si no hay sesión activa, redirige al login
        if 'usuario_id' not in session:
            flash("Debes iniciar sesión para acceder a esta página", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Verifica si un usuario ya ha respondido una encuesta en los últimos 30 días
def verificar_actividad_reciente(id_usuario):
    """Verifica si el usuario ha respondido la encuesta en los últimos 30 días"""
    cur = mysql.connection.cursor()
    
    # Se obtiene la fecha de la última respuesta registrada del usuario
    cur.execute("""
        SELECT fecha_respuesta FROM respuestas
        WHERE id_usuario = %s
        ORDER BY fecha_respuesta DESC
        LIMIT 1
    """, (id_usuario,))
    
    ultima_respuesta = cur.fetchone()
    
    if ultima_respuesta:
        fecha_ultima = ultima_respuesta[0]
        hace_un_mes = datetime.now() - timedelta(days=30)
        
        # Se compara si la última respuesta fue dentro de los últimos 30 días
        if fecha_ultima > hace_un_mes:
            return True  # Ya respondió recientemente
    
    return False  # No ha respondido en los últimos 30 días o no hay registros

# Enviar código de recuperación de contraseña por correo electrónico
def enviar_codigo_recuperacion(destinatario, codigo):
    """Envía un correo con el código de recuperación de contraseña"""
    try:
        # Desencripta el correo almacenado (si está cifrado)
        correo_desencriptado = desencriptar_dato(destinatario)
        
        # Crea el correo con asunto y contenido del código
        mensaje = EmailMessage()
        mensaje['Subject'] = 'Recuperación de Contraseña - Encuesta de Satisfacción'
        mensaje['From'] = EMAIL_SENDER
        mensaje['To'] = correo_desencriptado
        mensaje.set_content(f'''
        Hola,
        
        Has solicitado recuperar tu contraseña en nuestro sistema de encuestas de satisfacción.
        
        Tu código de verificación es: {codigo}
        
        Este código expirará en 30 minutos.
        
        Si no solicitaste este código, puedes ignorar este correo.
        
        Saludos,
        El equipo de Encuestas
        ''')

        # Envía el correo de manera segura usando SMTP con SSL
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(mensaje)

        # Registra el envío exitoso en el log
        logging.info(f"Código de recuperación enviado al correo: {correo_desencriptado}")
        return True

    except Exception as e:
        # Si hay un error, lo registra en el log
        logging.error(f"Error al enviar email de recuperación: {e}")
        return False


# --- Funciones auxiliares para gráficos ---

def generar_grafico_barras_seguro(datos, etiquetas, titulo, etiqueta_x, etiqueta_y, nombre_archivo, promedio=None):
    """Genera un gráfico de barras con validación de datos y manejo de errores"""

    plt.figure(figsize=(12, 6))  # Establecer el tamaño de la figura

    try:
        # Validar si hay datos y etiquetas suficientes
        if not datos or not etiquetas or len(datos) == 0 or len(etiquetas) == 0:
            raise ValueError("Datos insuficientes")

        # Convertir a arrays de NumPy para facilitar operaciones vectorizadas
        datos_array = np.array(datos)
        etiquetas_array = np.array(etiquetas)

        # Eliminar valores inválidos: NaN o negativos/cero
        mask = ~np.isnan(datos_array) & (datos_array > 0)
        datos_filtrados = datos_array[mask]
        etiquetas_filtradas = etiquetas_array[mask]

        if len(datos_filtrados) == 0:
            raise ValueError("No hay datos válidos después del filtrado")

        # Crear gráfico de barras con los datos filtrados
        barras = plt.bar(etiquetas_filtradas, datos_filtrados, color='#335435', alpha=0.8)

        # Agregar etiquetas de valores encima de cada barra
        for bar in barras:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.1f}', ha='center', va='bottom')

        # Si se proporciona el promedio, dibujar una línea horizontal roja
        if promedio is not None and not np.isnan(promedio):
            plt.axhline(y=promedio, color='r', linestyle='--', label=f'Promedio: {promedio:.1f}')
            plt.legend()

        # Ajustes del gráfico
        plt.ylim(0, max(datos_filtrados) * 1.15)  # Aumentar un poco el tope del eje Y
        plt.xticks(rotation=45, ha='right')       # Rotar etiquetas del eje X para mejor lectura
        plt.ylabel(etiqueta_y)
        plt.xlabel(etiqueta_x)
        plt.title(titulo)
        plt.tight_layout()  # Asegura que no se recorten elementos

    except Exception as e:
        # Si ocurre algún error durante la generación del gráfico
        plt.clf()  # Limpiar cualquier figura incompleta
        plt.text(0.5, 0.5, f'Error: {str(e)}', ha='center', va='center', fontsize=12)
        plt.title(titulo)  # Mostrar título aunque ocurra un error

    # Guardar el gráfico (o mensaje de error) como imagen en la carpeta correspondiente
    plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'), 
                bbox_inches='tight', dpi=100)
    plt.close()  # Cerrar la figura para liberar memoria
    
def generar_grafico_pastel_seguro(datos, etiquetas, titulo, nombre_archivo, colores=None):
    """
    Genera un gráfico de pastel de forma segura, manejando casos de datos vacíos
    """
    try:
        # Definir colores por defecto si no se pasan como parámetro
        if not colores:
            colores = ['#4CAF50', '#F44336', '#2196F3', '#FFC107', '#9C27B0', '#FF5722']
        
        # Validar que existan datos y etiquetas
        if not datos or not etiquetas or len(datos) == 0 or len(etiquetas) == 0:
            # Si no hay datos, mostrar un mensaje en lugar del gráfico
            plt.figure(figsize=(8, 8))
            plt.text(0.5, 0.5, 'No hay datos suficientes para mostrar', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=14)
            plt.title(titulo)
            plt.tight_layout()
            plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
            plt.close()
            return
        
        # Filtrar datos válidos (> 0) y sus etiquetas correspondientes
        datos_validos = []
        etiquetas_validas = []
        colores_validos = []
        
        for i, (dato, etiqueta) in enumerate(zip(datos, etiquetas)):
            if dato is not None and dato > 0:
                datos_validos.append(dato)
                etiquetas_validas.append(etiqueta)
                # Asignar color correspondiente o un color por defecto si se excede la lista
                if i < len(colores):
                    colores_validos.append(colores[i])
                else:
                    colores_validos.append('#888888')
        
        # Si no hay datos válidos después del filtrado, mostrar mensaje
        if len(datos_validos) == 0 or sum(datos_validos) == 0:
            plt.figure(figsize=(8, 8))
            plt.text(0.5, 0.5, 'No hay datos válidos para mostrar', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=14)
            plt.title(titulo)
            plt.tight_layout()
            plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
            plt.close()
            return
        
        # Crear gráfico de pastel con los datos válidos
        plt.figure(figsize=(8, 8))
        plt.pie(datos_validos, labels=etiquetas_validas, colors=colores_validos, 
                autopct='%1.1f%%', startangle=90, shadow=True)
        plt.axis('equal')  # Hace que el pastel sea un círculo perfecto
        plt.title(titulo)
        plt.tight_layout()
        plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
        plt.close()
        
    except Exception as e:
        print(f"Error al generar gráfico de pastel {nombre_archivo}: {e}")
        # Si ocurre un error, generar imagen con mensaje de error
        plt.figure(figsize=(8, 8))
        plt.text(0.5, 0.5, f'Error al generar gráfico: {str(e)}', 
                ha='center', va='center', transform=plt.gca().transAxes, fontsize=12)
        plt.title(titulo)
        plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
        plt.close()
        
def generar_grafico_histograma_seguro(datos, bins, etiquetas_bins, titulo, etiqueta_x, etiqueta_y, nombre_archivo):
    """
    Genera un histograma de forma segura, manejando casos de datos vacíos
    """
    try:
        # Verificar que se recibió una lista de datos no vacía
        if datos is None or len(datos) == 0:
            plt.figure(figsize=(10, 6))
            plt.text(0.5, 0.5, 'No hay datos suficientes para mostrar', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=14)
            plt.title(titulo)
            plt.xlabel(etiqueta_x)
            plt.ylabel(etiqueta_y)
            plt.tight_layout()
            plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
            plt.close()
            return
        
        # Eliminar valores nulos (usando Pandas o listas)
        datos_validos = datos.dropna() if hasattr(datos, 'dropna') else [d for d in datos if d is not None]
        
        # Si después del filtrado no hay datos válidos, mostrar mensaje
        if len(datos_validos) == 0:
            plt.figure(figsize=(10, 6))
            plt.text(0.5, 0.5, 'No hay datos válidos para mostrar', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=14)
            plt.title(titulo)
            plt.xlabel(etiqueta_x)
            plt.ylabel(etiqueta_y)
            plt.tight_layout()
            plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
            plt.close()
            return
        
        # Crear histograma con los datos válidos
        plt.figure(figsize=(10, 6))
        plt.hist(datos_validos, bins=bins, rwidth=0.8, color='#335435', alpha=0.8)  # rwidth ajusta separación entre barras
        
        # Si se proporcionaron etiquetas específicas para los bins, aplicarlas
        if etiquetas_bins:
            plt.xticks(etiquetas_bins)
        
        plt.xlabel(etiqueta_x)
        plt.ylabel(etiqueta_y)
        plt.title(titulo)
        plt.tight_layout()
        plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
        plt.close()
        
    except Exception as e:
        print(f"Error al generar histograma {nombre_archivo}: {e}")
        # Si ocurre error, mostrar mensaje dentro de una imagen
        plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, f'Error al generar gráfico: {str(e)}', 
                ha='center', va='center', transform=plt.gca().transAxes, fontsize=12)
        plt.title(titulo)
        plt.savefig(os.path.join(IMAGES_FOLDER, f'{nombre_archivo}.png'))
        plt.close()
        
def admin_required(f):
    """Decorador para proteger rutas que requieren privilegios de administrador"""
    
    @wraps(f)  # Preserva la metadata original de la función decorada (nombre, docstring, etc.)
    def decorated_function(*args, **kwargs):
        # Verificar si el usuario está autenticado (tiene 'usuario_id' en sesión)
        if 'usuario_id' not in session:
            # Si no está autenticado, mostrar mensaje y redirigir a la página de login
            flash("Debes iniciar sesión para acceder a esta página", "danger")
            return redirect(url_for('login'))
        
        # Verificar si el usuario tiene privilegios de administrador
        # Se asume que privilegios == 1 indica admin; cualquier otro valor no es admin
        if session.get('privilegios', 0) != 1:
            # Si no tiene permiso, mostrar mensaje de error
            flash("No tienes permiso para acceder a esta página", "danger")
            # Registrar en logs el intento no autorizado para auditoría
            logging.warning(f"Usuario {session.get('usuario_id')} intentó acceder a área de admin sin permisos")
            # Redirigir al usuario a la página de encuesta general (o página segura)
            return redirect(url_for('encuesta'))
        
        # Si pasó ambas verificaciones, ejecutar la función protegida normalmente
        return f(*args, **kwargs)
    
    return decorated_function

# ----- Rutas -----

@app.route('/')
def index():
    """Ruta principal que redirecciona automáticamente a la página de login"""
    return redirect(url_for('login'))  # Redirige a la función 'login'

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Ruta para el inicio de sesión del usuario"""
    
    error = None  # Variable para almacenar mensajes de error que se mostrarán en el template
    usuario = None  # Aquí se almacenará el usuario recuperado de la base de datos
    
    if request.method == 'POST':
        # Obtener datos del formulario, limpiando espacios en correo y obteniendo la contraseña
        correo = request.form.get('email', '').strip()
        contrasena = request.form.get('password', '')
        
        # Validar que ambos campos estén completos
        if not correo or not contrasena:
            error = "Por favor, completa todos los campos."
            return render_template('login.html', error=error)
        
        # Validar que el correo tenga un formato válido usando expresión regular
        if not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
            error = "Correo electrónico inválido"
            return render_template('login.html', error=error)
        
        # Buscar usuario en la base de datos por correo (se asume función que maneja desencriptación)
        usuario = buscar_usuario_por_correo(correo)
        
        # Si se encontró el usuario en la base de datos
        if usuario:
            # Revisar si el usuario NO está verificado (usuario[2] == 0)
            # y si tiene un código de verificación pendiente (usuario[5])
            if usuario[2] == 0 and usuario[5]:
                # Guardar correo en sesión para usarlo en la verificación
                session['correo_verificacion'] = correo
                # Mostrar mensaje informativo y redirigir a la página para ingresar código de verificación
                flash("Tu cuenta aún no ha sido verificada. Te hemos redirigido a la página de verificación.", "warning")
                return redirect(url_for('verificar_codigo'))
            
            # Verificar la contraseña usando check_password_hash (comparar hash con texto plano)
            if check_password_hash(usuario[4], contrasena):
                # Si el usuario está verificado (usuario[2] == 1)
                if usuario[2] == 1:
                    # Reiniciar contador de intentos fallidos en sesión (si existía)
                    if 'intentos_fallidos' in session:
                        session.pop('intentos_fallidos')
                    if 'email_intentos' in session:
                        session.pop('email_intentos')
                    
                    # Guardar datos del usuario en sesión para mantener autenticación
                    session['usuario_id'] = usuario[0]
                    session['nombre'] = usuario[1]
                    session['privilegios'] = usuario[3]
                    
                    logging.info(f"Inicio de sesión exitoso para usuario: {correo}")
                    
                    # Redirigir según el tipo de usuario
                    if usuario[3] == 1:  # Si es administrador
                        return redirect(url_for('admin_reportes_sucursal'))
                    else:  # Si es usuario normal
                        return redirect(url_for('encuesta'))
                else:
                    # Si el usuario no está verificado, guardamos correo para verificación y redirigimos
                    session['correo_verificacion'] = correo
                    flash("Tu cuenta aún no ha sido verificada. Por favor completa la verificación.", "warning")
                    return redirect(url_for('verificar_codigo'))
            else:
                # Contraseña incorrecta: registrar intento fallido
                logging.warning(f"Intento fallido de inicio de sesión para el correo: {correo}")
                
                # Manejar contador de intentos fallidos en sesión
                if 'intentos_fallidos' not in session or 'email_intentos' not in session or session['email_intentos'] != correo:
                    session['intentos_fallidos'] = 1
                    session['email_intentos'] = correo
                else:
                    session['intentos_fallidos'] += 1
                
                # Si se superan 3 intentos fallidos, redirigir a recuperación de contraseña
                if session.get('intentos_fallidos', 0) >= 3:
                    session['correo_recuperacion'] = correo
                    # Limpiar contador de intentos
                    session.pop('intentos_fallidos', None)
                    session.pop('email_intentos', None)
                    logging.warning(f"Múltiples intentos fallidos de inicio de sesión para: {correo}. Redirigiendo a recuperación.")
                    return redirect(url_for('recuperar_contrasena'))
                
                # Mostrar mensaje con cantidad de intentos restantes
                intentos_restantes = 3 - session.get('intentos_fallidos', 0)
                error = f"Contraseña incorrecta. Te quedan {intentos_restantes} intentos."
        else:
            # Si no se encuentra usuario con ese correo
            error = "No existe una cuenta con ese correo electrónico."
    
    # Renderizar plantilla login.html enviando mensaje de error si existe
    return render_template('login.html', error=error)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    """Ruta para el registro de nuevos usuarios"""
    
    error = None  # Variable para almacenar mensajes de error
    
    if request.method == 'POST':
        # Obtener y limpiar datos del formulario
        nombre = request.form.get('nombre', '').strip()
        apellido = request.form.get('apellido', '').strip()
        correo = request.form.get('correo', '').strip()
        telefono = request.form.get('telefono', '').strip()
        contrasena = request.form.get('contrasena', '')
        
        # Validación: Todos los campos son obligatorios
        if not all([nombre, apellido, correo, telefono, contrasena]):
            error = "Todos los campos son obligatorios"
            return render_template('registro.html', error=error)
        
        # Validar que el correo tenga formato válido mediante expresión regular
        if not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
            error = "Correo electrónico inválido"
            return render_template('registro.html', error=error)
        
        # Verificar si ya existe un usuario registrado con ese correo
        usuario_existente = buscar_usuario_por_correo(correo)
        if usuario_existente:
            error = "El correo ya está registrado"
        else:
            # Generar código único para verificación de cuenta
            codigo = generar_codigo_verificacion()
            
            # Hashear la contraseña usando función segura
            contrasena_hash = hash_password(contrasena)
            
            # Encriptar datos sensibles antes de guardar en BD
            correo_encriptado = encriptar_dato(correo)
            telefono_encriptado = encriptar_dato(telefono)
            
            # Insertar nuevo usuario en la base de datos
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO usuarios (privilegios, nombre, apellido, correo, telefono, contraseña, codigo_verificacion)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (0, nombre, apellido, correo_encriptado, telefono_encriptado, contrasena_hash, codigo))
            mysql.connection.commit()
            cur.close()
            
            # Enviar código de verificación por correo (se espera función que lo maneje)
            if enviar_codigo_verificacion(correo_encriptado, codigo):
                logging.info(f"Nuevo usuario registrado: {correo}")
                # Guardar correo en sesión para usar en la verificación
                session['correo_verificacion'] = correo
                # Redirigir a página para ingresar código de verificación
                return redirect(url_for('verificar_codigo'))
            else:
                # Si falla el envío del código, mostrar error
                error = "Error al enviar el código de verificación. Intenta de nuevo."
    
    # Renderizar la plantilla de registro con el posible mensaje de error
    return render_template('registro.html', error=error)

@app.route('/verificar_codigo', methods=['GET', 'POST'])
def verificar_codigo():
    """Ruta para verificar el código de confirmación enviado por correo"""
    
    mensaje = None  # Mensaje para mostrar al usuario
    verificado = False  # Indica si la cuenta ya fue verificada
    
    # Si no hay correo en sesión (no se llegó desde registro o login), redirigir al registro
    if 'correo_verificacion' not in session:
        return redirect(url_for('registro'))
    
    correo = session.get('correo_verificacion')
    
    # Manejar reenvío de código de verificación (GET con parámetro reenviar=true)
    reenviar = request.args.get('reenviar', 'false') == 'true'
    if request.method == 'GET' and reenviar:
        # Generar nuevo código de verificación
        codigo = generar_codigo_verificacion()
        
        # Buscar usuario en la BD por correo
        usuario = buscar_usuario_por_correo(correo)
        if usuario:
            cur = mysql.connection.cursor()
            # Actualizar el código en la base de datos
            cur.execute("""
                UPDATE usuarios 
                SET codigo_verificacion = %s 
                WHERE id_usuario = %s
            """, (codigo, usuario[0]))
            mysql.connection.commit()
            cur.close()
            
            # Enviar el nuevo código al correo (correo encriptado en usuario[6])
            if enviar_codigo_verificacion(usuario[6], codigo):
                mensaje = "Se ha enviado un nuevo código de verificación a tu correo."
            else:
                mensaje = "Error al enviar el código de verificación. Intenta nuevamente."
    
    if request.method == 'POST':
        # Obtener el código ingresado por el usuario
        codigo_usuario = request.form.get('codigo', '').strip()

        if not codigo_usuario:
            mensaje = "Por favor, ingresa el código de verificación"
        else:
            # Buscar nuevamente el usuario para comparar el código
            usuario = buscar_usuario_por_correo(correo)
            
            # Verificar si el código coincide con el guardado en la base de datos
            if usuario and usuario[5] == codigo_usuario:  # usuario[5] = codigo_verificacion
                cur = mysql.connection.cursor()
                # Actualizar la base de datos para marcar al usuario como verificado
                cur.execute("""
                UPDATE usuarios 
                SET codigo_verificacion = NULL, verificado = TRUE 
                WHERE id_usuario = %s
                """, (usuario[0],))
                mysql.connection.commit()
                cur.close()
                
                mensaje = "¡Cuenta verificada exitosamente!"
                verificado = True
                
                # Limpiar la sesión para no mantener el correo de verificación
                session.pop('correo_verificacion', None)
                
                # Mostrar mensaje de éxito y redirigir a login
                flash("Tu cuenta ha sido verificada. Ahora puedes iniciar sesión.", "success")
                logging.info(f"Cuenta verificada exitosamente para: {correo}")
                return redirect(url_for('login'))
            else:
                # Código incorrecto, mensaje y registro de intento fallido
                mensaje = "Código incorrecto. Intenta nuevamente."
                logging.warning(f"Intento fallido de verificación para el correo: {correo}")

    # Renderizar la plantilla con el mensaje, estado de verificación y correo
    # La plantilla puede incluir botón para reenviar código usando ?reenviar=true
    return render_template('verificar_codigo.html', mensaje=mensaje, verificado=verificado, correo=correo)

@app.route('/logout')
def logout():
    """Cierra la sesión del usuario limpiando todos los datos almacenados en session"""
    session.clear()
    flash("Has cerrado sesión correctamente", "success")
    return redirect(url_for('login'))


# Modificación de la ruta /encuesta para gestionar la encuesta y generar un cupón
@app.route('/encuesta', methods=['GET', 'POST'])
@login_required  # Asegura que el usuario esté autenticado
def encuesta():
    """Ruta para mostrar y procesar la encuesta de satisfacción"""

    id_usuario = session['usuario_id']

    # Verificar si el usuario ya respondió la encuesta en los últimos 30 días
    if verificar_actividad_reciente(id_usuario):
        flash("Ya has respondido la encuesta este mes. ¡Gracias!", "warning")
        return redirect(url_for('agradecimiento'))

    if request.method == 'POST':
        try:
            # Obtener y limpiar datos enviados en el formulario
            pais = request.form.get('pais', '').strip()
            sucursal = request.form.get('sucursal', '').strip()
            calidad_comida = int(request.form.get('calidad_comida', 0))
            tiempo_espera = request.form.get('tiempo_espera', '').strip()
            atencion_personal = int(request.form.get('atencion_personal', 0))
            agrado_sucursal = request.form.get('agrado_sucursal', '').strip()
            volveria_visitar = request.form.get('volveria_visitar', '').strip()
            area_mejora = request.form.get('area_mejora', '').strip()
            calificacion_general = int(request.form.get('calificacion_general', 0))

            # Validación simple para evitar campos vacíos obligatorios
            if not all([pais, sucursal, tiempo_espera, agrado_sucursal, volveria_visitar]):
                flash("Por favor, complete todos los campos requeridos", "danger")
                return redirect(url_for('encuesta'))

            # Guardar la respuesta en la base de datos
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO respuestas (
                    id_usuario, pais, sucursal, calidad_comida, tiempo_espera,
                    atencion_personal, agrado_sucursal, volveria_visitar,
                    area_mejora, calificacion_general, fecha_respuesta
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                id_usuario, pais, sucursal, calidad_comida, tiempo_espera,
                atencion_personal, agrado_sucursal, volveria_visitar,
                area_mejora, calificacion_general
            ))
            mysql.connection.commit()

            # Generar un cupón de descuento con porcentaje aleatorio entre 30%, 35% o 40%
            porcentajes = [30, 35, 40]
            porcentaje_elegido = random.choice(porcentajes)

            # Generar código único para el cupón (evitar duplicados)
            while True:
                codigo_cupon = generar_codigo_cupon()
                cur.execute("SELECT id_cupon FROM cupones WHERE codigo = %s", (codigo_cupon,))
                if not cur.fetchone():
                    break

            # Calcular fecha de vencimiento para el cupón (30 días desde hoy)
            fecha_vencimiento = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

            # Guardar cupón en la base de datos
            cur.execute("""
                INSERT INTO cupones (
                    id_usuario, codigo, porcentaje, fecha_vencimiento
                ) VALUES (%s, %s, %s, %s)
            """, (
                id_usuario, codigo_cupon, porcentaje_elegido, fecha_vencimiento
            ))
            mysql.connection.commit()

            # Obtener correo encriptado del usuario para enviar el cupón
            cur.execute("SELECT correo FROM usuarios WHERE id_usuario = %s", (id_usuario,))
            correo_usuario_encriptado = cur.fetchone()[0]

            cur.close()

            # Enviar cupón por correo electrónico (la función maneja desencriptación)
            enviar_cupon(correo_usuario_encriptado, codigo_cupon, porcentaje_elegido)

            flash("¡Gracias por tu respuesta! Te hemos enviado un cupón de descuento.", "success")
            return redirect(url_for('agradecimiento'))

        except Exception as e:
            # Capturar y registrar errores en el proceso
            print(f"Error al guardar la respuesta: {e}")
            logging.error(f"Error al guardar la respuesta: {e}")
            flash("Ocurrió un error. Intenta nuevamente.", "danger")
            return redirect(url_for('encuesta'))

    # Si es método GET, mostrar el formulario de encuesta
    return render_template('encuesta.html', nombre=session.get('nombre', ''))

@app.route('/agradecimiento')
@login_required  # Solo usuarios autenticados pueden acceder
def agradecimiento():
    """
    Muestra la página de agradecimiento que se presenta
    luego de que el usuario completa la encuesta.
    """
    return render_template('agradecimiento.html')

@app.route('/admin/reportes_sucursal')  # Ruta para acceder al panel de reportes de administrador
@login_required  # Decorador que verifica que el usuario esté autenticado
def admin_reportes_sucursal():
    """Página para visualizar reportes por sucursal"""
    # Verificar si el usuario es administrador
    if session.get('privilegios', 0) != 1:  # Solo usuarios con privilegio 1 (administrador) pueden acceder
        flash("No tienes permiso para acceder a esta página", "danger")
        return redirect(url_for('encuesta'))
    
    # Obtener parámetros de filtro desde la URL
    pais_seleccionado = request.args.get('pais', '')  # Filtro por país
    sucursal_seleccionada = request.args.get('sucursal', '')  # Filtro por sucursal específica
    fecha_inicio = request.args.get('fecha_inicio', '')  # Fecha de inicio del rango de consulta
    fecha_fin = request.args.get('fecha_fin', '')  # Fecha final del rango de consulta
    
    # Si no hay fechas seleccionadas, usar último mes
    if not fecha_inicio:
        fecha_inicio = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')  # Por defecto, últimos 30 días
    if not fecha_fin:
        fecha_fin = datetime.now().strftime('%Y-%m-%d')  # Por defecto, fecha actual
    
    # Consultar datos
    cur = mysql.connection.cursor()  # Crear cursor para ejecutar consultas SQL
    
    # Lista de países disponibles
    cur.execute("SELECT DISTINCT pais FROM respuestas ORDER BY pais")  # Obtener todos los países únicos
    paises = [row[0] for row in cur.fetchall()]  # Convertir resultado en lista simple
    
    # Lista de sucursales (filtradas por país si está seleccionado)
    if pais_seleccionado:
        cur.execute("SELECT DISTINCT sucursal FROM respuestas WHERE pais = %s ORDER BY sucursal", (pais_seleccionado,))  # Sucursales del país seleccionado
    else:
        cur.execute("SELECT DISTINCT sucursal FROM respuestas ORDER BY sucursal")  # Todas las sucursales
    sucursales = [row[0] for row in cur.fetchall()]  # Convertir resultado en lista simple
    
    # Construir consulta base con filtros para resumen
    query = """
        SELECT
            r.id_respuesta, 
            r.id_usuario, 
            r.pais, 
            r.sucursal, 
            COALESCE(r.calidad_comida, 0) AS calidad_comida,  # COALESCE maneja valores NULL, los convierte en 0
            r.tiempo_espera, 
            COALESCE(r.atencion_personal, 0) AS atencion_personal,  # COALESCE maneja valores NULL
            r.agrado_sucursal, 
            r.volveria_visitar, 
            r.area_mejora, 
            COALESCE(r.calificacion_general, 0) AS calificacion_general,  # COALESCE maneja valores NULL
            r.fecha_respuesta,
            u.nombre,
            u.apellido
        FROM respuestas r
        JOIN usuarios u ON r.id_usuario = u.id_usuario  # JOIN para obtener nombres de usuarios
        WHERE 1=1  # Condición base que siempre es verdadera para facilitar agregar filtros
    """
    # Manejo de parámetros de forma más segura
    params = []  # Lista para parámetros de la consulta SQL (previene inyección SQL)
    conditions = []  # Lista para condiciones WHERE adicionales
    
    if pais_seleccionado:
        conditions.append("r.pais = %s")  # Agregar condición de filtro por país
        params.append(pais_seleccionado)  # Agregar parámetro correspondiente
        
    if sucursal_seleccionada:
        conditions.append("r.sucursal = %s")  # Agregar condición de filtro por sucursal
        params.append(sucursal_seleccionada)  # Agregar parámetro correspondiente
        
    if fecha_inicio:
        conditions.append("r.fecha_respuesta >= %s")  # Filtro de fecha inicial
        params.append(fecha_inicio)  # Agregar parámetro de fecha inicial
        
    if fecha_fin:
        conditions.append("r.fecha_respuesta <= %s")  # Filtro de fecha final
        params.append(f"{fecha_fin} 23:59:59")  # Incluir todo el día final hasta las 23:59:59
        
    # Combinar condiciones si existen
    if conditions:
        query += " AND " + " AND ".join(conditions)  # Unir todas las condiciones con AND
        
    # Ordenamiento
    query += " ORDER BY r.fecha_respuesta DESC"  # Ordenar por fecha más reciente primero
    
    # Ejecutar consulta
    try:
        cur.execute(query, tuple(params))  # Ejecutar consulta con parámetros seguros
        datos = cur.fetchall()  # Obtener todos los resultados
    
        # Verificar que tenemos datos
        if not datos:
            flash("No se encontraron resultados con los filtros aplicados", "info")  # Notificar si no hay datos
            datos = []  # Inicializar lista vacía
        
    except Exception as e:
        flash(f"Error al consultar la base de datos: {str(e)}", "danger")  # Mostrar error al usuario
        logging.error(f"Error en consulta SQL: {str(e)}")  # Log del error para debugging
        datos = []  # Lista vacía en caso de error
    
    # Cerrar cursor
    cur.close()  # Liberar recursos de base de datos
    
    # Inicializar variables por defecto
    total_respuestas = 0  # Contador total de respuestas
    promedio_calificacion = 0  # Promedio general de calificaciones
    satisfaccion_servicio = 0  # Promedio de satisfacción del servicio
    tasa_retorno = 0  # Porcentaje de clientes que volverían
    datos_sucursales = []  # Lista para datos agrupados por sucursal
    respuestas_tabla = []  # Lista para mostrar respuestas individuales en tabla
    
    # Procesar datos con pandas solo si hay datos
    if datos and len(datos) > 0:
        try:
            # Nombres de columnas según tu estructura de tablas
            columnas = ['id_respuesta', 'id_usuario', 'pais', 'sucursal', 'calidad_comida', 
                        'tiempo_espera', 'atencion_personal', 'agrado_sucursal', 
                        'volveria_visitar', 'area_mejora', 'calificacion_general', 
                        'fecha_respuesta', 'nombre', 'apellido']  # Definir nombres de columnas para DataFrame
            
            # Crear DataFrame
            df = pd.DataFrame(datos, columns=columnas)  # Convertir datos SQL en DataFrame de pandas

            # Convertir explícitamente las columnas numéricas
            df['calificacion_general'] = pd.to_numeric(df['calificacion_general'], errors='coerce')  # Convertir a numérico, NaN si falla
            df['calidad_comida'] = pd.to_numeric(df['calidad_comida'], errors='coerce')  # Convertir a numérico
            df['atencion_personal'] = pd.to_numeric(df['atencion_personal'], errors='coerce')  # Convertir a numérico

            # Calcular métricas asegurando que los valores son numéricos
            total_respuestas = len(df)  # Contar total de filas

            # Calcular promedios solo con valores válidos
            promedio_calificacion = round(df['calificacion_general'].mean(), 1) if not df['calificacion_general'].isna().all() else 0  # Promedio de calificación general
            satisfaccion_servicio = round(df['atencion_personal'].mean() * 10, 1) if not df['atencion_personal'].isna().all() else 0  # Promedio de atención * 10

            # Para volveria_visitar, contar las respuestas afirmativas
            tasa_retorno = round((df['volveria_visitar'] == 'si').sum() / df['volveria_visitar'].count() * 100, 1) if df['volveria_visitar'].count() > 0 else 0  # Porcentaje de "sí"

            # Procesar datos por sucursal
            sucursales_grupo = df.groupby('sucursal')  # Agrupar DataFrame por sucursal

            for sucursal, grupo in sucursales_grupo:  # Iterar por cada grupo de sucursal
                # Calcular indicadores para cada sucursal
                total_sucursal = len(grupo)  # Total de respuestas por sucursal
                
                # Calidad comida (promedio)
                calidad_promedio = round(grupo['calidad_comida'].mean(), 1) if not grupo['calidad_comida'].isna().all() else 0  # Promedio calidad comida
                
                # Atención personal (promedio)
                atencion_promedio = round(grupo['atencion_personal'].mean(), 1) if not grupo['atencion_personal'].isna().all() else 0  # Promedio atención personal
                
                # Tiempo de espera (porcentaje de respuestas 'si')
                tiempo_adecuado = round((grupo['tiempo_espera'] == 'si').sum() / grupo['tiempo_espera'].count() * 100, 1) if grupo['tiempo_espera'].count() > 0 else 0  # % tiempo adecuado
                
                # Calificación general (promedio)
                calificacion_promedio = round(grupo['calificacion_general'].mean(), 1) if not grupo['calificacion_general'].isna().all() else 0  # Promedio calificación general
                
                # Intención de retorno (porcentaje de respuestas 'si')
                intencion_retorno = round((grupo['volveria_visitar'] == 'si').sum() / grupo['volveria_visitar'].count() * 100, 1) if grupo['volveria_visitar'].count() > 0 else 0  # % intención retorno
                
                datos_sucursales.append({  # Agregar métricas de sucursal a la lista
                    'sucursal': sucursal,
                    'total_respuestas': total_sucursal,
                    'calidad_comida': calidad_promedio,
                    'atencion_personal': atencion_promedio,
                    'tiempo_espera': tiempo_adecuado,
                    'calificacion_general': calificacion_promedio,
                    'intencion_retorno': intencion_retorno
                })

            # Ordenar por calificación general (descendente)
            datos_sucursales = sorted(datos_sucursales, key=lambda x: x['calificacion_general'], reverse=True)  # Ordenar por mejor calificación

            # GENERAR GRÁFICOS SOLO SI HAY DATOS VÁLIDOS
            
            # 1. Gráfico de calificaciones por sucursal
            if len(datos_sucursales) > 0:
                try:
                    sucursales_plot = datos_sucursales[:10] if len(datos_sucursales) > 10 else datos_sucursales  # Limitar a 10 sucursales para visualización
                    nombres_sucursales = [item['sucursal'] for item in sucursales_plot]  # Extraer nombres de sucursales
                    calificaciones = [item['calificacion_general'] for item in sucursales_plot]  # Extraer calificaciones
                    
                    # Verificar que tenemos datos válidos para el gráfico
                    if len(nombres_sucursales) > 0 and len(calificaciones) > 0 and any(c > 0 for c in calificaciones):  # Validar datos para graficar
                        plt.figure(figsize=(12, 6))  # Crear figura con tamaño específico
                        plt.bar(nombres_sucursales, calificaciones, color='#335435', alpha=0.8)  # Crear gráfico de barras
                        plt.axhline(y=promedio_calificacion, color='r', linestyle='--', 
                                    label=f'Promedio: {promedio_calificacion}')  # Línea horizontal con promedio
                        plt.ylim(0, 5.5)  # Establecer límites del eje Y
                        plt.xticks(rotation=45, ha='right')  # Rotar etiquetas del eje X
                        plt.ylabel('Calificación Promedio')  # Etiqueta eje Y
                        plt.title('Calificación Promedio por Sucursal')  # Título del gráfico
                        plt.legend()  # Mostrar leyenda
                        plt.tight_layout()  # Ajustar layout para evitar cortes
                        plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_sucursales.png'))  # Guardar gráfico como imagen
                        plt.close()  # Cerrar figura para liberar memoria
                except Exception as e:
                    print(f"Error generando gráfico de sucursales: {e}")  # Log de error
                    # Crear imagen vacía como fallback
                    plt.figure(figsize=(12, 6))
                    plt.text(0.5, 0.5, 'Sin datos suficientes para mostrar gráfico', 
                            ha='center', va='center', transform=plt.gca().transAxes)  # Mensaje de sin datos
                    plt.title('Calificación Promedio por Sucursal')
                    plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_sucursales.png'))  # Guardar imagen fallback
                    plt.close()
            
            # 2. Gráfico de distribución de calificaciones
            try:
                valid_ratings = df['calificacion_general'].dropna()  # Eliminar valores NaN
                if len(valid_ratings) > 0 and valid_ratings.sum() > 0:  # Verificar que hay datos válidos
                    plt.figure(figsize=(10, 6))
                    plt.hist(valid_ratings, bins=[0.5, 1.5, 2.5, 3.5, 4.5, 5.5], 
                            rwidth=0.8, color='#335435', alpha=0.8)  # Crear histograma con bins específicos
                    plt.xticks([1, 2, 3, 4, 5])  # Etiquetas del eje X
                    plt.xlabel('Calificación')  # Etiqueta eje X
                    plt.ylabel('Número de Respuestas')  # Etiqueta eje Y
                    plt.title('Distribución de Calificaciones Generales')  # Título
                    plt.tight_layout()
                    plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_distribucion.png'))  # Guardar gráfico
                    plt.close()
                else:
                    # Crear imagen vacía como fallback
                    plt.figure(figsize=(10, 6))
                    plt.text(0.5, 0.5, 'Sin datos suficientes para mostrar distribución', 
                            ha='center', va='center', transform=plt.gca().transAxes)  # Mensaje de sin datos
                    plt.title('Distribución de Calificaciones Generales')
                    plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_distribucion.png'))
                    plt.close()
            except Exception as e:
                print(f"Error generando gráfico de distribución: {e}")  # Log de error
                
            # 3. Gráfico de pastel para intención de retorno
            try:
                volveria_counts = df['volveria_visitar'].value_counts()  # Contar valores únicos de "volvería a visitar"
                si_count = volveria_counts.get('si', 0)  # Obtener cantidad de "sí"
                no_count = volveria_counts.get('no', 0)  # Obtener cantidad de "no"
                
                if si_count > 0 or no_count > 0:  # Verificar que hay datos
                    plt.figure(figsize=(8, 8))
                    counts = [si_count, no_count]  # Lista de valores
                    labels = ['Sí', 'No']  # Etiquetas
                    colors = ['#4CAF50', '#F44336']  # Colores verde y rojo
                    
                    # Filtrar valores cero para evitar problemas
                    filtered_counts = []
                    filtered_labels = []
                    filtered_colors = []
                    
                    for i, count in enumerate(counts):  # Iterar por cada valor
                        if count > 0:  # Solo incluir valores mayores a 0
                            filtered_counts.append(count)
                            filtered_labels.append(labels[i])
                            filtered_colors.append(colors[i])
                    
                    if len(filtered_counts) > 0:  # Si hay datos filtrados
                        plt.pie(filtered_counts, labels=filtered_labels, colors=filtered_colors, 
                               autopct='%1.1f%%', startangle=90, shadow=True)  # Crear gráfico de pastel
                        plt.axis('equal')  # Mantener proporción circular
                        plt.title('Intención de Retorno')  # Título
                        plt.tight_layout()
                        plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_retorno.png'))  # Guardar gráfico
                        plt.close()
                    else:
                        # Crear imagen vacía como fallback
                        plt.figure(figsize=(8, 8))
                        plt.text(0.5, 0.5, 'Sin datos suficientes para mostrar intención de retorno', 
                                ha='center', va='center', transform=plt.gca().transAxes)
                        plt.title('Intención de Retorno')
                        plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_retorno.png'))
                        plt.close()
                else:
                    # Crear imagen vacía como fallback
                    plt.figure(figsize=(8, 8))
                    plt.text(0.5, 0.5, 'Sin datos de intención de retorno', 
                            ha='center', va='center', transform=plt.gca().transAxes)
                    plt.title('Intención de Retorno')
                    plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_retorno.png'))
                    plt.close()
            except Exception as e:
                print(f"Error generando gráfico de retorno: {e}")  # Log de error
                
            # Preparar datos para la tabla de respuestas individuales
            df['fecha_respuesta'] = pd.to_datetime(df['fecha_respuesta'], errors='coerce')  # Convertir a datetime
            df['fecha_formateada'] = df['fecha_respuesta'].apply(lambda x: x.strftime('%d/%m/%Y %H:%M') if pd.notnull(x) else '')  # Formatear fecha

            
            # Crear lista de respuestas para mostrar en la tabla
            for _, row in df.iterrows():  # Iterar por cada fila del DataFrame
                respuestas_tabla.append({  # Agregar respuesta formateada a la tabla
                    'nombre': f"{row['nombre']} {row['apellido']}",  # Nombre completo
                    'fecha': row['fecha_formateada'],  # Fecha formateada
                    'calidad_comida': row['calidad_comida'],  # Calificación calidad comida
                    'tiempo_espera': 'Sí' if row['tiempo_espera'] == 'si' else 'No',  # Convertir a Sí/No
                    'atencion_personal': row['atencion_personal'],  # Calificación atención
                    'agrado_sucursal': 'Sí' if row['agrado_sucursal'] == 'si' else 'No',  # Convertir a Sí/No
                    'volveria_visitar': 'Sí' if row['volveria_visitar'] == 'si' else 'No',  # Convertir a Sí/No
                    'area_mejora': row['area_mejora'],  # Área de mejora sugerida
                    'calificacion_general': row['calificacion_general']  # Calificación general
                })
                
        except Exception as e:
            print(f"Error procesando datos: {e}")  # Log de error en procesamiento
            logging.error(f"Error procesando datos en reportes: {e}")  # Log detallado
            # Mantener valores por defecto si hay error
            pass
    else:
        # Sin datos - crear gráficos vacíos
        try:
            # Gráfico de sucursales vacío
            plt.figure(figsize=(12, 6))
            plt.text(0.5, 0.5, 'No hay datos para mostrar', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=14)  # Mensaje sin datos
            plt.title('Calificación Promedio por Sucursal')
            plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_sucursales.png'))
            plt.close()
            
            # Gráfico de distribución vacío
            plt.figure(figsize=(10, 6))
            plt.text(0.5, 0.5, 'No hay datos para mostrar', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=14)  # Mensaje sin datos
            plt.title('Distribución de Calificaciones Generales')
            plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_distribucion.png'))
            plt.close()
            
            # Gráfico de retorno vacío
            plt.figure(figsize=(8, 8))
            plt.text(0.5, 0.5, 'No hay datos para mostrar', 
                    ha='center', va='center', transform=plt.gca().transAxes, fontsize=14)  # Mensaje sin datos
            plt.title('Intención de Retorno')
            plt.savefig(os.path.join(IMAGES_FOLDER, 'chart_retorno.png'))
            plt.close()
        except Exception as e:
            print(f"Error creando gráficos vacíos: {e}")  # Log de error
    
    return render_template('reportes_admin.html',  # Renderizar template con todos los datos
                          paises=paises,  # Lista de países para filtros
                          sucursales=sucursales,  # Lista de sucursales para filtros
                          pais_seleccionado=pais_seleccionado,  # País seleccionado actualmente
                          sucursal_seleccionada=sucursal_seleccionada,  # Sucursal seleccionada actualmente
                          fecha_inicio=fecha_inicio,  # Fecha de inicio del filtro
                          fecha_fin=fecha_fin,  # Fecha final del filtro
                          total_respuestas=total_respuestas,  # Total de respuestas encontradas
                          promedio_calificacion=promedio_calificacion,  # Promedio general de calificaciones
                          satisfaccion_servicio=satisfaccion_servicio,  # Promedio de satisfacción del servicio
                          tasa_retorno=tasa_retorno,  # Porcentaje de intención de retorno
                          datos_sucursales=datos_sucursales,  # Datos agrupados por sucursal
                          respuestas=respuestas_tabla)  # Respuestas individuales para tabla
    
@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    """
    Ruta para solicitar recuperación de contraseña mediante correo.
    Envia un código de verificación para permitir cambiar la contraseña.
    """
    error = None
    mensaje = None
    
    # Verificar si el usuario fue redirigido con correo en sesión tras intentos fallidos
    correo_redirect = session.get('correo_recuperacion', '')
    
    if request.method == 'POST':
        correo = request.form.get('email', '').strip()
        
        # Validar que el correo no esté vacío
        if not correo:
            error = "Por favor, ingresa tu correo electrónico"
        # Validar formato del correo con regex
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
            error = "Correo electrónico inválido"
        else:
            # Buscar usuario en la base de datos por correo (desencriptando)
            usuario = buscar_usuario_por_correo(correo)
            
            if usuario:
                # Generar un código único para la recuperación
                codigo = generar_codigo_verificacion()
                
                # Guardar el código y la fecha en la base de datos
                cur = mysql.connection.cursor()
                cur.execute("""
                UPDATE usuarios 
                SET codigo_verificacion = %s, fecha_codigo = NOW()
                WHERE id_usuario = %s
                """, (codigo, usuario[0]))
                mysql.connection.commit()
                cur.close()
                
                # Enviar el código al correo encriptado del usuario
                if enviar_codigo_recuperacion(usuario[6], codigo):  # usuario[6] es correo encriptado
                    session['correo_recuperacion'] = correo  # Guardar correo en sesión para el flujo
                    mensaje = "Se ha enviado un código de verificación a tu correo"
                    logging.info(f"Solicitud de recuperación de contraseña para: {correo}")
                    # Redirigir para que el usuario ingrese el código recibido
                    return redirect(url_for('verificar_codigo_recuperacion'))
                else:
                    error = "Error al enviar el código. Intenta nuevamente."
            else:
                # Si no existe usuario con ese correo
                error = "No existe una cuenta con ese correo electrónico"
                logging.warning(f"Intento de recuperación para correo inexistente: {correo}")
    
    # Caso GET: si usuario fue redirigido desde login y aún no ha enviado formulario
    elif correo_redirect and request.method == 'GET':
        usuario = buscar_usuario_por_correo(correo_redirect)
        
        if usuario:
            # Generar código para recuperación
            codigo = generar_codigo_verificacion()
            
            # Guardar el código y fecha en BD
            cur = mysql.connection.cursor()
            cur.execute("""
            UPDATE usuarios 
            SET codigo_verificacion = %s, fecha_codigo = NOW()
            WHERE id_usuario = %s
            """, (codigo, usuario[0]))
            mysql.connection.commit()
            cur.close()
            
            # Enviar el código al correo del usuario
            if enviar_codigo_recuperacion(usuario[6], codigo):  # correo encriptado
                mensaje = f"Se ha enviado un código de verificación a {correo_redirect}"
                logging.info(f"Solicitud de recuperación de contraseña (redireccionada) para: {correo_redirect}")
                return redirect(url_for('verificar_codigo_recuperacion'))
            else:
                error = "Error al enviar el código. Intenta nuevamente."
        else:
            error = "No existe una cuenta con ese correo electrónico"
    
    # Renderizar la plantilla, enviando mensajes y correo prellenado si aplica
    return render_template('recuperar_contrasena.html', error=error, mensaje=mensaje, correo_prefill=correo_redirect)

@app.route('/verificar_codigo_recuperacion', methods=['GET', 'POST'])
def verificar_codigo_recuperacion():
    """
    Ruta para que el usuario ingrese y verifique el código de recuperación
    enviado a su correo, para poder cambiar su contraseña.
    """
    error = None
    
    # Si no hay correo guardado en sesión, redirigir a recuperar contraseña
    if 'correo_recuperacion' not in session:
        return redirect(url_for('recuperar_contrasena'))
    
    if request.method == 'POST':
        codigo = request.form.get('codigo', '').strip()  # Código ingresado por el usuario
        correo = session.get('correo_recuperacion')      # Obtener correo desde sesión
        
        if not codigo:
            error = "Por favor, ingresa el código de verificación"
        else:
            # Buscar usuario por correo (la función maneja el correo encriptado)
            usuario = buscar_usuario_por_correo(correo)
            
            # Verificar que el usuario exista y que el código coincida con el de la BD
            if usuario and usuario[5] == codigo:  # usuario[5] es codigo_verificacion
                # Consultar la fecha en que se generó el código
                cur = mysql.connection.cursor()
                cur.execute("SELECT fecha_codigo FROM usuarios WHERE id_usuario = %s", (usuario[0],))
                resultado = cur.fetchone()
                cur.close()
                
                if resultado and resultado[0]:
                    tiempo_actual = datetime.now()
                    tiempo_codigo = resultado[0]
                    
                    # Verificar que el código no haya expirado (30 minutos)
                    if (tiempo_actual - tiempo_codigo).total_seconds() <= 1800:  # 1800 segundos = 30 minutos
                        # Código válido y dentro del tiempo permitido
                        # Guardar estado de verificación en sesión
                        session['codigo_verificado'] = True
                        session['usuario_recuperacion_id'] = usuario[0]
                        logging.info(f"Código de recuperación verificado para: {correo}")
                        
                        # Redirigir para que el usuario cambie su contraseña
                        return redirect(url_for('nueva_contrasena'))
                    else:
                        # Código expirado
                        error = "El código ha expirado. Solicita uno nuevo."
                        logging.warning(f"Intento de usar código expirado para: {correo}")
                else:
                    # No se pudo obtener fecha de código desde BD (error inesperado)
                    error = "Error al verificar el código. Intenta nuevamente."
            else:
                # Código incorrecto
                error = "Código incorrecto. Intenta nuevamente."
                logging.warning(f"Intento fallido de verificación para recuperación de contraseña: {correo}")
    
    # Renderizar plantilla con posible mensaje de error
    return render_template('verificar_codigo_recuperacion.html', error=error)

@app.route('/nueva_contrasena', methods=['GET', 'POST'])
def nueva_contrasena():
    """
    Ruta para que el usuario establezca una nueva contraseña después de
    haber verificado el código de recuperación.
    """
    error = None
    
    # Validar que el usuario haya pasado por las etapas previas necesarias
    # Es decir, que haya solicitado recuperación y verificado el código
    if 'correo_recuperacion' not in session or 'codigo_verificado' not in session or 'usuario_recuperacion_id' not in session:
        # Si falta alguno, redirigir para iniciar el proceso nuevamente
        return redirect(url_for('recuperar_contrasena'))
    
    if request.method == 'POST':
        # Obtener las contraseñas ingresadas por el usuario
        nueva_contrasena = request.form.get('nueva_contrasena', '')
        confirmar_contrasena = request.form.get('confirmar_contrasena', '')
        
        # Validar que ambos campos estén completos
        if not nueva_contrasena or not confirmar_contrasena:
            error = "Por favor, completa todos los campos"
        # Validar que las contraseñas coincidan
        elif nueva_contrasena != confirmar_contrasena:
            error = "Las contraseñas no coinciden"
        # Validar longitud mínima de la contraseña
        elif len(nueva_contrasena) < 6:
            error = "La contraseña debe tener al menos 6 caracteres"
        else:
            # Encriptar la nueva contraseña usando función hash
            contrasena_hash = hash_password(nueva_contrasena)
            usuario_id = session.get('usuario_recuperacion_id')
            
            # Actualizar la contraseña en la base de datos, limpiar código y fecha de verificación
            cur = mysql.connection.cursor()
            cur.execute("""
                UPDATE usuarios 
                SET contraseña = %s, codigo_verificacion = NULL, fecha_codigo = NULL
                WHERE id_usuario = %s
            """, (contrasena_hash, usuario_id))
            mysql.connection.commit()
            cur.close()
            
            # Guardar correo para logging antes de limpiar sesión
            correo = session.get('correo_recuperacion')
            # Limpiar variables de sesión relacionadas al proceso de recuperación
            session.pop('correo_recuperacion', None)
            session.pop('codigo_verificado', None)
            session.pop('usuario_recuperacion_id', None)
            
            logging.info(f"Contraseña actualizada exitosamente para: {correo}")
            # Mostrar mensaje de éxito al usuario
            flash("Tu contraseña ha sido actualizada exitosamente", "success")
            # Redirigir a login para que ingrese con la nueva contraseña
            return redirect(url_for('login'))
    
    # Renderizar la plantilla con posibles mensajes de error
    return render_template('nueva_contrasena.html', error=error)

@app.route('/static/images/<filename>')
def serve_image(filename):
    """
    Ruta para servir imágenes estáticas que se generan o guardan en la carpeta definida por IMAGES_FOLDER.
    Esto permite acceder a imágenes por URL como /static/images/nombre.jpg
    """
    return send_from_directory(IMAGES_FOLDER, filename)


@app.errorhandler(404)
def pagina_no_encontrada(error):
    """
    Manejador personalizado para errores HTTP 404 (Página no encontrada).
    Renderiza una plantilla 404.html para mostrar un mensaje amigable al usuario.
    """
    return render_template('404.html'), 404


@app.errorhandler(500)
def error_servidor(error):
    """
    Manejador personalizado para errores HTTP 500 (Error interno del servidor).
    Renderiza una plantilla 500.html para mostrar un mensaje amigable en caso de fallo grave.
    """
    return render_template('500.html'), 500


@app.context_processor
def inject_cache_buster():
    """
    Inyecta una variable 'cache_buster' con el timestamp actual en el contexto de las plantillas.
    Esto se puede usar para evitar problemas de caché en recursos estáticos agregando ?v={{ cache_buster }} 
    al final de URLs de CSS, JS o imágenes.
    """
    return dict(cache_buster=datetime.now().timestamp())


if __name__ == "__main__":
    # Configura el puerto de la aplicación según variable de entorno PORT, útil para despliegues como en Render.com
    port = int(os.environ.get('PORT', 5000))
    # Activar modo debug solo si la variable FLASK_ENV está en 'development' (evitar en producción)
    debug = os.environ.get('FLASK_ENV') == 'development'
    # Ejecutar la aplicación Flask, escuchando en todas las interfaces (0.0.0.0)
    app.run(host='0.0.0.0', port=port, debug=debug)