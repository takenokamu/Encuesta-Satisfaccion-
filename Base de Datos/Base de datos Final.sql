CREATE DATABASE `encuestas_db` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;

CREATE TABLE `usuarios` (
  `id_usuario` int NOT NULL AUTO_INCREMENT,
  `privilegios` int NOT NULL DEFAULT '0',
  `nombre` varchar(50) NOT NULL,
  `apellido` varchar(50) NOT NULL,
  `correo` varchar(100) NOT NULL,
  `telefono` varchar(15) NOT NULL,
  `contraseña` varchar(255) NOT NULL,
  `fecha_registro` datetime DEFAULT CURRENT_TIMESTAMP,
  `verificado` tinyint(1) DEFAULT '0',
  `codigo_verificacion` varchar(6) DEFAULT NULL,
  `fecha_codigo` datetime DEFAULT NULL,
  PRIMARY KEY (`id_usuario`),
  UNIQUE KEY `correo` (`correo`),
  UNIQUE KEY `telefono_UNIQUE` (`telefono`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `respuestas` (
  `id_respuesta` int NOT NULL AUTO_INCREMENT,
  `pais` varchar(50) DEFAULT NULL,
  `sucursal` varchar(50) DEFAULT NULL,
  `calidad_comida` int DEFAULT NULL,
  `tiempo_espera` enum('si','no') DEFAULT NULL,
  `atencion_personal` int DEFAULT NULL,
  `agrado_sucursal` enum('si','no') DEFAULT NULL,
  `volveria_visitar` enum('si','no') DEFAULT NULL,
  `area_mejora` text,
  `calificacion_general` int DEFAULT NULL,
  `fecha_respuesta` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `id_usuario` int DEFAULT NULL,
  PRIMARY KEY (`id_respuesta`),
  KEY `fk_usuario_respuesta` (`id_usuario`),
  CONSTRAINT `fk_usuario_respuesta` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `cupones` (
  `id_cupon` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int NOT NULL,
  `codigo` varchar(6) NOT NULL,
  `porcentaje` int NOT NULL,
  `fecha_emision` datetime DEFAULT CURRENT_TIMESTAMP,
  `fecha_vencimiento` datetime NOT NULL,
  `utilizado` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id_cupon`),
  UNIQUE KEY `codigo_UNIQUE` (`codigo`),
  KEY `fk_usuario_cupon` (`id_usuario`),
  CONSTRAINT `fk_usuario_cupon` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id_usuario`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

