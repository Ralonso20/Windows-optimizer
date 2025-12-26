# Windows Optimizer - All In One

> Script completo de optimización y limpieza para Windows 11 con interfaz gráfica

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-green.svg)
![Windows](https://img.shields.io/badge/Windows-11-0078D6.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

<img width="1382" height="890" alt="imagen" src="https://github.com/user-attachments/assets/4a08fd24-fc60-43cd-b3ad-b2222bef8e4a" />

---

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Perfiles Predefinidos](#-perfiles-predefinidos)
- [Modo Personalizado](#-modo-personalizado)
- [Funciones Disponibles](#-funciones-disponibles)
- [Sistema de Backup](#-sistema-de-backup)
- [Advertencias](#%EF%B8%8F-advertencias)
- [Solución de Problemas](#-solución-de-problemas)
- [Créditos](#-créditos)

---

## ✨ Características

### 🎨 Interfaz Gráfica Moderna
- GUI intuitiva con perfiles predefinidos
- Modo personalizado con checkboxes
- Barra de progreso en tiempo real
- Sistema de indicadores de severidad (SEGURO/MODERADO/AGRESIVO)
- Ventana redimensionable con scroll automático

### 🎯 3 Perfiles Predefinidos
1. **Gaming PC** - Máximo rendimiento para juegos
2. **Trabajo/Oficina** - Optimizado y activado
3. **Limpieza Básica** - Conservador y seguro

### ⚙️ Modo Personalizado
- Más de 20 optimizaciones seleccionables
- Categorías organizadas (Limpieza, Rendimiento, Sistema, Agresivas)
- Indicadores visuales de severidad por color
- Descripciones detalladas de cada opción

### 💾 Sistema de Backup
- Backup automático antes de cada cambio
- Ventana de restauración con historial
- Log detallado de todas las acciones
- Botón dedicado para reinstalar Edge

---

## 📦 Requisitos

- **OS**: Windows 11 (build 22000+)
- **PowerShell**: 5.1 o superior
- **Permisos**: Administrador
- **Espacio**: ~50MB para backups
- **Dependencias**: 
  - `7z` (para parche de ISO)
  - `xorriso` (para parche de ISO)

---

## 🚀 Instalación

### Método 1: Ejecución Directa (Recomendado)

```powershell
# Abrir PowerShell como Administrador
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\Windows-Optimizer-Clean.ps1
```

### Método 2: Bypass Temporal

```powershell
powershell -ExecutionPolicy Bypass -File .\Windows-Optimizer-Clean.ps1
```

### Método 3: Desbloquear Archivo

```powershell
Unblock-File -Path .\Windows-Optimizer-Clean.ps1
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\Windows-Optimizer-Clean.ps1
```

---

## 🎮 Uso

### Interfaz Principal

```
┌──────────────────────────────────────────────────────────┐
│      WINDOWS OPTIMIZER - Selecciona tu perfil           │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  GAMING PC  │  │   TRABAJO   │  │   BASICO    │     │
│  │             │  │  /OFICINA   │  │             │     │
│  │ * Bloatware │  │ * Bloatware │  │ * Bloatware │     │
│  │ * WebView2  │  │ * WebView2  │  │ * Telemetria│     │
│  │ * Telemetria│  │ * Telemetria│  │ * Cortana   │     │
│  │ * Game Mode │  │ * SSD       │  │ * Busqueda  │     │
│  │ * GPU       │  │ * Activar   │  │ * Limpieza  │     │
│  │ * Red       │  │   Windows   │  │             │     │
│  │ * SSD       │  │ * Activar   │  │             │     │
│  │ * Servicios │  │   Office    │  │             │     │
│  │             │  │             │  │             │     │
│  │[  APLICAR  ]│  │[  APLICAR  ]│  │[  APLICAR  ]│     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                          │
│  [PERSONALIZADO] [RESTAURAR] [SALIR]                    │
└──────────────────────────────────────────────────────────┘
```

---

## 🎯 Perfiles Predefinidos

### 🎮 Gaming PC

**Objetivo**: Máximo rendimiento en juegos

**Incluye**:
- ✅ Eliminar bloatware
- ✅ Optimizar WebView2 (sin romper apps)
- ✅ Deshabilitar telemetría
- ✅ Deshabilitar Cortana
- ✅ Búsqueda solo local
- ✅ Game Mode ON
- ✅ GPU optimizada (Hardware-accelerated scheduling)
- ✅ Red optimizada (latencia reducida)
- ✅ SSD optimizado (TRIM, desfrag OFF)
- ✅ Servicios innecesarios OFF (~40 servicios)
- ✅ Limpieza archivos temp
- ✅ Plan alto rendimiento
- ✅ Windows Update: Solo seguridad

**Resultado**: Sistema limpio y máximo FPS

---

### 💼 Trabajo/Oficina

**Objetivo**: Sistema limpio y activado

**Incluye**:
- ✅ Eliminar bloatware
- ✅ Optimizar WebView2
- ✅ Deshabilitar telemetría
- ✅ Deshabilitar Cortana
- ✅ Búsqueda solo local
- ✅ SSD optimizado
- ✅ Limpieza archivos temp
- ✅ **Activar Windows** (MAS)
- ✅ **Activar Office** (MAS)
- ✅ Windows Update: Seguridad + Drivers

**Resultado**: Sistema profesional activado

---

### 🧹 Limpieza Básica

**Objetivo**: Limpieza conservadora sin cambios agresivos

**Incluye**:
- ✅ Eliminar bloatware
- ✅ Optimizar WebView2
- ✅ Deshabilitar telemetría
- ✅ Deshabilitar Cortana
- ✅ Búsqueda solo local
- ✅ Limpieza archivos temp

**NO Incluye**:
- ❌ Gaming optimizations
- ❌ Activación
- ❌ Cambios agresivos

**Resultado**: Limpieza segura y conservadora

---

## ⚙️ Modo Personalizado

### Categorías de Optimización

#### 🧹 LIMPIEZA Y PRIVACIDAD

| Opción | Descripción | Nivel |
|--------|-------------|-------|
| Eliminar Bloatware | Elimina apps preinstaladas (Xbox, Mapas, etc.) | 🟢 SEGURO |
| Optimizar WebView2 | Limpia cache, updates manuales (apps funcionan) | 🟢 SEGURO |
| Deshabilitar Telemetría | Sin envío de datos a Microsoft | 🟢 SEGURO |
| Deshabilitar Cortana | Asistente de voz OFF | 🟢 SEGURO |
| Búsqueda Solo Local | Sin Bing en búsqueda | 🟢 SEGURO |
| Deshabilitar OneDrive | Desinstala (reinstalable) | 🟠 MODERADO |
| Eliminar OneDrive | Eliminación completa + limpieza | 🔴 AGRESIVO |

#### ⚡ RENDIMIENTO

| Opción | Descripción | Nivel |
|--------|-------------|-------|
| Game Mode ON | Optimiza recursos para juegos | 🟢 SEGURO |
| Optimizar GPU | Hardware-accelerated GPU scheduling | 🟢 SEGURO |
| Optimizar Red | Reduce latencia, mejora velocidad | 🟢 SEGURO |
| Optimizar SSD | TRIM, desfrag OFF, prefetch OFF | 🟢 SEGURO |
| Plan Alto Rendimiento | Máximo rendimiento de CPU | 🟠 MODERADO |
| Deshabilitar Servicios | ~40 servicios innecesarios OFF | 🟠 MODERADO |
| Limpiar Temp | Elimina archivos temporales | 🟢 SEGURO |

#### 🔧 SISTEMA Y ACTUALIZACIONES

| Opción | Descripción | Nivel |
|--------|-------------|-------|
| Update: Solo Seguridad | Windows Update conservador | 🟢 SEGURO |
| Update: Seguridad + Drivers | Incluye drivers | 🟢 SEGURO |
| Activar Windows | MAS activation (HWID) | 🟠 MODERADO |
| Activar Office | MAS activation (Ohook) | 🟠 MODERADO |

#### ⚠️ OPCIONES AGRESIVAS

| Opción | Descripción | Nivel |
|--------|-------------|-------|
| Deshabilitar Defender | Antivirus OFF | 🔴 AGRESIVO |
| Deshabilitar UAC | Control de cuentas OFF | 🔴 AGRESIVO |
| Deshabilitar Firewall | Firewall OFF | 🔴 AGRESIVO |
| Eliminar Edge | Desinstala Edge completamente | 🔴 AGRESIVO |
| Eliminar IA de Windows | Copilot, Recall, etc. OFF | 🟠 MODERADO |

---

## 🛠️ Funciones Disponibles

### Limpieza y Privacidad

#### `Disable-Bloatware`
Elimina aplicaciones preinstaladas innecesarias.

**Apps eliminadas**:
- Microsoft.3DBuilder
- Microsoft.BingNews, BingWeather
- Microsoft.Xbox* (todas las apps Xbox)
- Microsoft.WindowsMaps
- Microsoft.MixedReality.Portal
- Microsoft.YourPhone
- Y más... (~30 apps)

---

#### `Optimize-WebView2`
Optimiza WebView2 sin romper Discord, Teams, Spotify.

**Acciones**:
- ✅ Deshabilita actualizaciones automáticas
- ✅ Limpia cache (~varios MB)
- ✅ Reduce prioridad de procesos
- ✅ Apps siguen funcionando normalmente

---

#### `Disable-Telemetry`
Deshabilita recolección de datos de uso.

**Servicios deshabilitados**:
- DiagTrack
- dmwappushservice
- WerSvc
- OneSyncSvc
- MessagingService

**Tareas deshabilitadas**:
- Microsoft Compatibility Appraiser
- ProgramDataUpdater
- CEIP Tasks

---

#### `Disable-Cortana`
Deshabilita el asistente de voz Cortana.

---

#### `Disable-WebSearch`
Configura búsqueda solo para archivos locales (sin Bing).

**Claves de registro modificadas**:
- BingSearchEnabled = 0
- DisableWebSearch = 1
- ConnectedSearchUseWeb = 0

---

### Rendimiento

#### `Enable-GameMode`
Activa Game Mode para optimizar recursos en juegos.

---

#### `Optimize-GPU`
Habilita Hardware-accelerated GPU scheduling.

**Requiere**: GPU compatible (GTX 1000+, RX 5000+)

---

#### `Optimize-Network`
Reduce latencia y mejora velocidad de conexión.

**Optimizaciones**:
- QoS packet scheduler optimizado
- TCP autotuninglevel = normal
- Chimney, DCA, NetDMA habilitados

---

#### `Optimize-SSD`
Optimiza SSD para mayor vida útil y rendimiento.

**Acciones**:
- ✅ Deshabilita desfragmentación automática
- ✅ Habilita TRIM
- ✅ Deshabilita Prefetch y Superfetch
- ✅ Deshabilita indexación (opcional)
- ✅ Optimiza archivo de paginación (tamaño fijo)
- ✅ Deshabilita hibernación (libera espacio = RAM)

---

#### `Set-HighPerformance`
Configura el plan de energía de alto rendimiento.

---

#### `Disable-UnnecessaryServices`
Deshabilita ~40 servicios innecesarios.

**Servicios deshabilitados**:
- Xbox services (XblAuthManager, XblGameSave, etc.)
- Print Spooler (si no usas impresora)
- Fax Service
- Telephony services
- Windows Search (opcional)
- Biometric services
- Geolocation
- Maps
- Tablet PC services
- Windows Media Player Network Sharing
- Y más...

**NOTA**: Bluetooth NO se deshabilita.

---

#### `Clean-TempFiles`
Limpia archivos temporales del sistema.

**Carpetas limpiadas**:
- `%TEMP%`
- `C:\Windows\Temp`
- `%LOCALAPPDATA%\Temp`
- `C:\Windows\Prefetch`
- Thumbnails cache
- Icon cache
- Windows Update cache
- Memory dumps

**Muestra**: Cantidad de MB liberados

---

### Sistema

#### `Activate-Windows`
Activa Windows usando Microsoft Activation Scripts (MAS).

**Método**: HWID (permanente)

**Comando**:
```powershell
irm https://get.activated.win | iex
```

---

#### `Activate-Office`
Activa Office usando MAS.

**Método**: Ohook

---

#### `Update-SecurityOnly`
Configura Windows Update solo para actualizaciones de seguridad.

---

#### `Update-SecurityAndDrivers`
Incluye también actualizaciones de drivers.

---

### Opciones Agresivas

#### `Disable-WindowsDefender`
⚠️ **PELIGROSO**: Deshabilita Windows Defender completamente.

**NO recomendado** a menos que uses otro antivirus.

---

#### `Disable-UAC`
⚠️ **PELIGROSO**: Deshabilita Control de Cuentas de Usuario.

Reduce seguridad significativamente.

---

#### `Disable-Firewall`
⚠️ **PELIGROSO**: Deshabilita Firewall de Windows.

Solo si estás detrás de un firewall de hardware.

---

#### `Remove-Edge`
🔴 **AGRESIVO**: Elimina Microsoft Edge completamente.

**Acciones**:
- Desinstala Edge usando setup oficial
- Elimina carpetas residuales
- Elimina accesos directos

**Restaurar**: Usa el botón "REINSTALAR EDGE" en la ventana de Restauración.

---

#### `Remove-WindowsAI`
🟠 **MODERADO**: Elimina características de IA de Windows 11.

Basado en: [RemoveWindowsAI](https://github.com/zoicware/RemoveWindowsAI)

**Elimina/Deshabilita**:
- ✅ **Copilot** (completamente)
- ✅ **Recall** (AI Data Analysis)
- ✅ **Input Insights** (predicción de texto)
- ✅ **Rewrite** en Notepad
- ✅ **Image Creator** en Paint
- ✅ **Voice Access**
- ✅ Paquetes Appx de IA
- ✅ Tareas programadas de IA
- ✅ Servicios de IA

---

### Restauración

#### `Restore-Edge`
Reinstala Microsoft Edge automáticamente.

**Descarga**: Instalador oficial de Microsoft

**Botón dedicado**: En ventana de "Restaurar Configuración"

---

## 💾 Sistema de Backup

### Ubicación
```
C:\Users\[Usuario]\Desktop\WindowsOptimizer_Backup\
```

### Formato de Archivos
```
backup_2025-12-26_14-30-45.txt
```

### Contenido del Backup
```
=== BACKUP: Perfil Gaming ===
Fecha: 2025-12-26 14:30:45
====================================

Servicio: DiagTrack - Estado: Running, Tipo inicio: Automatic
App eliminada: Microsoft.XboxApp
Cortana deshabilitada
...
```

### Restauración

1. Click en **RESTAURAR CONFIGURACIÓN**
2. Selecciona el backup deseado
3. Click en **RESTAURAR SELECCIONADO**
4. Se abre el archivo para revisión manual

**Nota**: La restauración es semi-automática. Algunos cambios requieren intervención manual.

---

## ⚠️ Advertencias

### 🔴 Opciones Agresivas

Las opciones marcadas como **AGRESIVAS** pueden:
- Reducir la seguridad del sistema
- Romper funcionalidades de Windows
- Causar problemas con actualizaciones
- Requerir reinstalación de componentes

**Usa bajo tu propio riesgo**.

---

### 🟠 Opciones Moderadas

Las opciones **MODERADAS** pueden:
- Requerir configuración manual posterior
- Afectar compatibilidad con algunas apps
- Necesitar reinstalación ocasional

---

### 🟢 Opciones Seguras

Las opciones **SEGURAS**:
- Son reversibles
- No afectan funcionalidad crítica
- Mejoran rendimiento sin riesgos

---

## 🔧 Solución de Problemas

### Error: "El archivo no está firmado digitalmente"

**Solución**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

O:
```powershell
Unblock-File -Path .\Windows-Optimizer-Clean.ps1
```

---

### Error: "Necesita ejecutarse como Administrador"

**Solución**:
1. Click derecho en PowerShell
2. "Ejecutar como Administrador"
3. Ejecutar el script

---

### Aplicaciones no funcionan después de eliminar Edge

**Solución**:
1. Abre "RESTAURAR CONFIGURACIÓN"
2. Click en "REINSTALAR MICROSOFT EDGE"
3. Espera a que termine la instalación

---

### Discord/Teams no funciona después de WebView2

**Causa**: Esto NO debería pasar. La función `Optimize-WebView2` no rompe apps.

**Solución**: Si pasa, reinstala la app afectada.

---

### Windows no activa con MAS

**Posibles causas**:
- Sin conexión a internet
- Antivirus bloqueando
- Windows ya activado

**Solución**:
1. Verifica conexión a internet
2. Deshabilita antivirus temporalmente
3. Ejecuta manualmente:
```powershell
irm https://get.activated.win | iex
```

---

### SSD más lento después de optimizar

**Causa**: Algunos SSD requieren prefetch.

**Solución**:
```powershell
# Rehabilitar Prefetch
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 3
```

---

## 📝 Notas Importantes

### Activación de Windows/Office

El script usa **Microsoft Activation Scripts (MAS)**, que es:
- ✅ Open source
- ✅ Seguro
- ✅ Usado por millones
- ✅ Activación permanente (HWID)

**Sitio oficial**: https://massgrave.dev

---

### Servicios que NO se deshabilitan

Por compatibilidad y funcionalidad:
- ✅ **Bluetooth** (muchos usan auriculares/mouse)
- ✅ **Windows Update** (solo se configura)
- ✅ **Audio** (esencial)
- ✅ **Red** (esencial)

---

### WebView2

- ✅ Discord funciona
- ✅ Teams funciona
- ✅ Spotify funciona
- ✅ Edge funciona (si está instalado)
- ✅ Apps de Electron funcionan

Solo se deshabilitan actualizaciones automáticas.

---

## 🎨 Capturas de Pantalla

### Ventana Principal
```
┌──────────────────────────────────────────────────────────┐
│      WINDOWS OPTIMIZER - Selecciona tu perfil           │
├──────────────────────────────────────────────────────────┤
│  [GAMING PC]    [TRABAJO/OFICINA]    [LIMPIEZA BASICA]  │
│  [MODO PERSONALIZADO] [RESTAURAR] [SALIR]               │
└──────────────────────────────────────────────────────────┘
```

### Modo Personalizado
```
┌──────────────────────────────────────────────────────────┐
│  SELECCIONA LAS OPTIMIZACIONES QUE DESEAS APLICAR       │
├──────────────────────────────────────────────────────────┤
│  ═══════ LIMPIEZA Y PRIVACIDAD ═══════                  │
│  ☑ [SEGURO] Eliminar Bloatware                          │
│  ☑ [SEGURO] Optimizar WebView2                          │
│  ☐ [MODERADO] Deshabilitar OneDrive                     │
│                                                          │
│  ═══════ RENDIMIENTO ═══════                            │
│  ☑ [SEGURO] Optimizar SSD                               │
│  ☑ [MODERADO] Deshabilitar Servicios                    │
│                                                          │
│  Optimizando GPU...  ████████░░░░  60%                  │
│                                                          │
│  [APLICAR SELECCION]              [CANCELAR]            │
└──────────────────────────────────────────────────────────┘
```

---

## 📄 Licencia

MIT License - Uso libre

---

## 🙏 Créditos

### Inspiración y Referencias
- [RemoveWindowsAI](https://github.com/zoicware/RemoveWindowsAI) - Eliminación de características de IA
- [Microsoft Activation Scripts](https://massgrave.dev) - Activación de Windows/Office
- Comunidad de optimización de Windows

### Desarrollado por
- Script: Rodri
- Versión: 2.0 Advanced
- Fecha: Diciembre 2024

---

## 🔄 Changelog

### v2.0 (Actual)
- ✅ Modo personalizado con barra de progreso
- ✅ Optimización de WebView2
- ✅ Eliminación de Edge + Restauración
- ✅ Eliminación de IA de Windows
- ✅ Optimización de SSD
- ✅ Búsqueda solo local
- ✅ ~40 servicios deshabilitables
- ✅ Limpieza de archivos temporales
- ✅ Sistema de backup mejorado
- ✅ GUI responsive y scrollable
- ✅ Indicadores de severidad por color

### v1.0
- Perfiles básicos (Gaming, Trabajo, Básico)
- Deshabilitación de telemetría
- Eliminación de bloatware
- Activación de Windows/Office

---

## ⚡ Inicio Rápido

```powershell
# 1. Descargar el script
# 2. Abrir PowerShell como Administrador
# 3. Ejecutar:

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
cd C:\Users\[TuUsuario]\Downloads
.\Windows-Optimizer-Clean.ps1

# 4. Seleccionar perfil o usar Modo Personalizado
# 5. ¡Listo!
```

---

**¡Disfruta de un Windows 11 optimizado! 🚀**
