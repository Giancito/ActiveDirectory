# ActiveDirectory-AdminCount-Review

Script PowerShell para auditoría y remediación controlada de objetos Active Directory con `AdminCount=1`.

---

# Descripción

Este proyecto permite identificar usuarios, grupos y equipos que mantienen el atributo `AdminCount=1` en Active Directory, validando si realmente continúan siendo objetos protegidos o si se trata de configuraciones heredadas que deben ser regularizadas.

El script está orientado a ambientes enterprise y procesos de hardening Active Directory.

---

# Funcionalidades

## Auditoría de objetos protegidos

El script identifica:

- Usuarios con `AdminCount=1`
- Grupos con `AdminCount=1`
- Equipos con `AdminCount=1`
- Objetos con herencia ACL deshabilitada
- Objetos potencialmente huérfanos

---

## Validación inteligente

Incluye validaciones para reducir falsos positivos:

- Validación de grupos protegidos
- Validación mediante `tokenGroups`
- Validación de membresías privilegiadas
- Exclusión de objetos realmente protegidos

---

## Generación de reportes

El script genera:

- Reporte CSV
- Logs detallados
- Evidencia de ejecución
- Resultado de auditoría y remediación

---

## Remediación controlada

En modo remediación el script puede:

- Limpiar el atributo `AdminCount`
- Rehabilitar herencia ACL
- Mantener objetos protegidos sin cambios
- Evitar remediaciones inseguras

---

# Modos de ejecución

## Modo auditoría

```powershell
.\Review-AdminCount_TechMentor.ps1 -Mode Report
```

---

## Modo remediación

```powershell
.\Review-AdminCount_TechMentor.ps1 -Mode Remediate
```

---

## Ruta personalizada para reportes

```powershell
.\Review-AdminCount_TechMentor.ps1 -Mode Report -OutputPath "C:\Temp\AdminCount"
```

---

# Casos de uso

Este script resulta útil para:

- Hallazgos Purple Knight
- Hallazgos PingCastle
- Hardening Active Directory
- Revisiones Tiering
- Cleanup de privilegios heredados
- Auditorías Microsoft
- Revisiones de delegación
- Proyectos de seguridad Microsoft
- Revisiones post migración

---

# Recomendaciones

## Antes de ejecutar

Se recomienda:

- Ejecutar primero en modo `Report`
- Validar resultados antes de remediar
- Ejecutar cambios bajo control de cambios
- Probar previamente en laboratorio
- Mantener respaldo de Active Directory

---

# Requisitos

- Windows PowerShell
- Active Directory PowerShell Module
- Permisos de lectura en Active Directory
- Permisos elevados para remediación

---

# Riesgo de AdminCount mal gestionado

En muchas organizaciones, los objetos mantienen `AdminCount=1` durante años aun cuando ya no pertenecen a grupos privilegiados.

Esto puede provocar:

- Herencia ACL deshabilitada
- Delegaciones incorrectas
- Persistencia de privilegios
- Riesgo de movimiento lateral
- Hallazgos críticos en auditorías
- Problemas de administración delegada

---

# Objetivo del proyecto

El objetivo de este proyecto es ayudar a la comunidad Microsoft a mejorar la seguridad de Active Directory mediante automatización segura y controlada.

Muchas veces los riesgos más críticos no provienen de malware avanzado, sino de configuraciones heredadas que permanecen sin revisión durante años.

Compartir herramientas reales utilizadas en proyectos de consultoría ayuda a elevar el nivel técnico de la comunidad.

---

# Autor

## Giancarlo Lopez Plasencia

Consultor Senior de Seguridad e Infraestructura Microsoft  
TECHMENTOR CONSULTING

Especialista en:

- Microsoft Security
- Active Directory
- Zero Trust
- Microsoft 365
- PKI / AD CS
- Conditional Access
- Defender XDR

---

# GitHub

https://github.com/Giancito

---

# LinkedIn

https://www.linkedin.com/in/giancarlolopezplasencia/

---

# Disclaimer

Este proyecto es compartido únicamente con fines educativos y de apoyo técnico.

Toda remediación debe ser previamente validada en ambientes de prueba.

El autor y TECHMENTOR CONSULTING no se responsabilizan por impactos derivados del uso incorrecto del script, ejecución sin validación previa o ausencia de control de cambios.

---

# Licencia

MIT License
