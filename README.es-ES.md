# wiretap-rs

[![Release](https://img.shields.io/github/v/release/0xTriboulet/wiretap-rs?display_name=tag)](https://github.com/0xTriboulet/wiretap-rs/releases)
[![Build Status](https://github.com/0xTriboulet/wiretap-rs/workflows/Rust/badge.svg)](https://github.com/0xTriboulet/wiretap-rs/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**wiretap-rs** es un puerto en Rust de [Wiretap](https://github.com/sandialabs/wiretap), un servidor proxy transparente, similar a una VPN, que tuneliza el tráfico a través de WireGuard y no requiere privilegios especiales para ejecutarse.

Este proyecto tiene como objetivo lograr la paridad funcional con la implementación original en Go, manteniendo un código Rust idiomático y un enfoque de desarrollo guiado por pruebas (TDD). La implementación funciona tanto como una librería que puede integrarse en otros proyectos de Rust mediante `cargo add wiretap-rs`, como una aplicación de línea de comandos independiente.

## Descripción General

Wiretap es un servidor proxy transparente, similar a una VPN, que tuneliza el tráfico a través de WireGuard y no requiere privilegios especiales para ejecutarse.

### Terminología

**Wiretap Server**: Una máquina donde el binario de Wiretap está ejecutando el comando `serve`. Los servidores reciben y retransmiten el tráfico de red en nombre de los Clientes de Wiretap, actuando como un "nodo de salida" de VPN.

**Wiretap Client**: Una máquina que ejecuta las configuraciones de [WireGuard](https://www.wireguard.com/) necesarias para enviar y recibir tráfico de red a través de un Servidor de Wiretap. Funciona de manera muy similar a un cliente en una conexión VPN. Los clientes también pueden reconfigurar partes de la red de Wiretap dinámicamente utilizando el binario de Wiretap.

> **Importante:** A diferencia del uso típico de los términos "cliente" y "servidor" en redes, los términos Cliente y Servidor de Wiretap no tienen nada que ver con qué máquina escucha o inicia la conexión inicial.

### Cómo funciona

Wiretap ejecuta una interfaz WireGuard de **relay** y una interfaz WireGuard **E2EE** (Cifrado de Extremo a Extremo) anidada opcional, totalmente en el espacio de usuario. Termina los túneles de WireGuard y redirige el tráfico hacia la red del host utilizando una pila TCP/UDP de espacio de usuario (smoltcp) más los sockets del sistema operativo. Una pequeña API HTTP gestiona la asignación de pares, la introspección de la topología y la exposición de puertos.

**Componentes Clave:**
- **Túnel WireGuard de Relay**: Transporta paquetes entre pares sobre UDP.
- **Túnel WireGuard E2EE**: Anidado sobre el túnel de relay para el cifrado de extremo a extremo.
- **Ruta de datos en espacio de usuario**: 
  - Los paquetes TCP/UDP son manejados por smoltcp y puenteados a TcpStream/UdpSocket del OS.
  - El echo ICMP se maneja creando respuestas cuando el ping del sistema tiene éxito.
- **API sobre el túnel**: La API HTTP se sirve a través de la dirección del túnel, no mediante un socket vinculado al host.
- **Exponer (Expose)**: La exposición TCP/UDP/Dinámica (SOCKS5) se implementa a través de la API y se enruta a través del túnel.
- **Persistencia del estado de asignación**: Instantáneas de asignación de direcciones opcionales mediante `WIRETAP_ALLOCATION_STATE`.

## Instalación

### Binarios Pre-compilados

Descarga los binarios pre-compilados para tu plataforma desde la [página de Releases](https://github.com/0xTriboulet/wiretap-rs/releases).

Plataformas disponibles:
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows (x86_64)

### Compilación desde el Código Fuente

**Prerrequisitos:** Toolchain de Rust (stable). Instálalo desde [https://rustup.rs/](https://rustup.rs/)

```bash
# Clonar el repositorio
git clone https://github.com/0xTriboulet/wiretap-rs.git
cd wiretap-rs

# Compilar el proyecto
cargo build
cargo build --release

# El binario estará en target/release/wiretap-rs
```

### Compilación con CMake/cmkr (para integración en C/C++)

Este repositorio también soporta un wrapper de CMake alrededor de las compilaciones de Cargo para que los proyectos de C/C++ puedan consumirlo con FetchContent o add_subdirectory.

**Prerrequisitos:** Toolchain de Rust + CMake + cmkr

```bash
# Generar CMakeLists.txt desde cmake.toml (si es necesario)
cmkr

# Compilación de depuración (Debug)
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug

# Compilación de lanzamiento (Release)
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
```

El objetivo de CMake importado es `wiretap_rs::wiretap_rs` y los encabezados públicos se encuentran en `include/`.

### Uso como Librería

Añade wiretap-rs a tu proyecto de Rust:

```bash
cargo add wiretap-rs
```

O añádelo a tu `Cargo.toml`:

```toml
[dependencies]
wiretap-rs = "0.1"
```

### Uso desde C/C++

`wiretap-rs` expone un punto de entrada de despacho de comandos C ABI que reutiliza el analizador de CLI de Rust:

- `int32_t wiretap_run_argv(int argc, const char* const* argv);`
- `char* wiretap_last_error_message(void);`
- `void wiretap_string_free(char* ptr);`

Encabezado: `include/wiretap_rs.h`

`wiretap_last_error_message()` devuelve memoria propia; liberala siempre con `wiretap_string_free()`.

## Primeros Pasos

### Prerrequisitos

**Para el Cliente:**
- [WireGuard](https://www.wireguard.com/install/) instalado.
- Acceso privilegiado para configurar interfaces de WireGuard (normalmente acceso root/administrador).

**Para el Servidor:**
- Toolchain de Rust (stable) si se compila desde el código fuente.
- Capacidad para ejecutar el binario de Wiretap (no se requieren privilegios especiales).
- Puertos UDP accesibles (por defecto: 51820 para relay, 51821 para E2EE).
- Binario `ping` disponible si se requiere el manejo de echo ICMP.

**Requisitos del Entorno:**
- Comunicación UDP bidireccional entre el Servidor y el Cliente en al menos un puerto.
- Cualquier firewall entre ellos debe permitir que al menos una máquina inicie una conexión UDP hacia la otra.

### Compilar y Probar

```bash
cargo build
cargo test
```

El binario se genera en `target/debug/wiretap-rs` (o `target/release/wiretap-rs` para compilaciones de release). Puedes añadirlo a tu PATH o ejecutarlo directamente desde la raíz del proyecto.

### Generar Archivos de Configuración

El comando `configure` genera configuraciones para el cliente y un archivo de configuración para el servidor.

Los puertos predeterminados son 51820 (relay) y 51821 (E2EE). Puedes anular el puerto de relay del servidor con `--sport` o configurando el puerto en `--endpoint`/`--outbound-endpoint`.
Añade `--clipboard` para copiar el comando de servidor POSIX generado en el portapapeles de tu sistema.

**Conexión entrante típica (El Cliente se conecta al Servidor):**

```bash
wiretap-rs configure \
  --endpoint 203.0.113.10:<server-port-number> \
  --routes 10.0.0.0/24 \
  --server-output wiretap_server.conf
```

**Modo simple (solo relay, configuración de un solo cliente):**

```bash
wiretap-rs configure \
  --endpoint 203.0.113.10:<server-port-number> \
  --routes 10.0.0.0/24 \
  --simple
```

### Ejecutar el Servidor

```bash
wiretap-rs serve -f wiretap_server.conf
```

**Modo silencioso (sin salida de consola ni archivos de registro):**

```bash
wiretap-rs serve -f wiretap_server.conf --quiet
```

**Archivo de estado de asignación (persistencia de direcciones):**

Establece `WIRETAP_ALLOCATION_STATE=/path/to/state.json` para habilitar el estado de asignación persistente.

### Iniciar el Cliente

- **Modo normal**: Inicia el relay **primero**, luego el E2EE (se requieren ambas configuraciones).
  ```bash
  wg-quick up wiretap_relay.conf
  wg-quick up wiretap.conf
  ```

- **Modo simple**: Solo una configuración.
  ```bash
  wg-quick up wiretap.conf
  ```

### Comandos de la API

Estos comandos interactúan con la API a través del túnel:

```bash
wiretap-rs expose --help
wiretap-rs ping --server-address ::2
wiretap-rs status --help
wiretap-rs add --help
```

## Guía de Prueba Manual

Usa esta secuencia para validar una instalación nueva de extremo a extremo.

### 1. Generar Archivos de Configuración

```bash
wiretap-rs configure \
  --endpoint <server-public-ip>:<server-port-number> \
  --routes 10.0.0.0/24 \
  --server-output wiretap_server.conf
```

**Salidas:**
- `wiretap_relay.conf` (configuración de relay del cliente)
- `wiretap.conf` (configuración E2EE del cliente)
- `wiretap_server.conf` (configuración del servidor)

### 2. Copiar la Configuración del Servidor al Servidor

```bash
scp wiretap_server.conf user@<server-public-ip>:/path/to/wiretap_server.conf
```

### 3. Iniciar el Servidor

```bash
wiretap-rs serve -f /path/to/wiretap_server.conf
```

### 4. Iniciar los Túneles del Cliente

**Modo normal (relay primero, luego E2EE):**

```bash
wg-quick up wiretap_relay.conf
wg-quick up wiretap.conf
```

**Modo simple:**

```bash
wg-quick up wiretap.conf
```

### 5. Confirmar los Handshakes de WireGuard

```bash
wg show wiretap_relay
wg show wiretap
```

### 6. Probar la API a Través del Túnel

- **API predeterminada IPv6:**
  ```bash
  curl http://[::2]/ping
  ```
- **API IPv4 cuando IPv6 está deshabilitado:**
  ```bash
  curl http://192.0.2.2/ping
  ```

### 7. Probar el Reenvío TCP con Mapeo de Localhost

Vuelve a generar las configuraciones con un mapeo de localhost:

```bash
wiretap-rs configure \
  --outbound-endpoint <server-public-ip>:<server-port-number> \
  --routes 10.0.0.0/24 \
  --localhost-ip 10.0.0.123
```

**En el servidor:**

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

**Desde el cliente:**

```bash
curl http://10.0.0.123:8080
```

### 8. Desmontar

```bash
wg-quick down wiretap.conf
wg-quick down wiretap_relay.conf
```

## Limitaciones Actuales

Este puerto a Rust está en desarrollo activo para alcanzar la paridad con la implementación original en Go. Las limitaciones actuales incluyen:

- **Solo espacio de usuario**: No se realizan cambios en la interfaz WireGuard del kernel ni en el enrutamiento a nivel de OS; el tráfico se proxifica en el espacio de usuario.
- **Cobertura de protocolos**: Se admiten TCP/UDP/echo ICMP; otros protocolos aún no han sido implementados.
- **Seguridad de la API**: La API no está autenticada (coincide con la implementación de referencia en Go).
- **Diferencias en la pila de red**: El comportamiento de smoltcp puede diferir del de gVisor; se esperan diferencias en casos borde del manejo de TCP/UDP.
- **Ergonomía operativa**: No hay unidades de systemd ni configuración automática de firewall/NAT.

Para una compatibilidad conductual estricta con Go, consulta las pruebas en `tests/` como la fuente de verdad para la paridad y las brechas abiertas.

## Registros (Logging)

`wiretap-rs` utiliza registros estructurados a través de `tracing`.

**Predeterminados:**
- Las compilaciones de depuración (Debug) escriben logs en `./logs/wiretap-<epoch>.log` y también en stdout.
- Las compilaciones de lanzamiento (Release) registran solo en stdout.

**Configuración (todo opcional):**
- `WIRETAP_LOG_FILE=/path/to/file.log` - Ruta explícita del archivo de registro.
- `WIRETAP_LOG_DIR=/path/to/dir` - Directorio para el archivo de registro.
- `WIRETAP_LOG_LEVEL=info|debug|trace` - Nivel de registro (o usa `RUST_LOG`).
- `WIRETAP_QUIET=1` - Desactiva los registros en stdout (equivalente a la bandera `--quiet`).

## Estructura del Proyecto

- `src/` - Implementación en Rust.
- `reference/` - Implementación original en Go (como referencia).
- `tests/` - Pruebas de integración en Rust (validación de paridad y comportamiento).
- `development_documentation/` - Notas de especificación y progreso del puerto.

## Contribución

Este puerto prioriza la paridad guiada por pruebas con la implementación de referencia original en Go. Si añades un nuevo comportamiento:
1. Añade las pruebas correspondientes.
2. Actualiza `development_documentation/porting_progress.md`.

## Sobre el Wiretap Original

Este proyecto se basa en [Wiretap](https://github.com/sandialabs/wiretap), desarrollado originalmente por los Laboratorios Nacionales Sandia. El puerto a Rust tiene como objetivo mantener la compatibilidad y la paridad de funciones aprovechando las ventajas de rendimiento y seguridad de Rust.

Para más información sobre el diseño y las capacidades de Wiretap, consulta el [repositorio del proyecto original](https://github.com/sandialabs/wiretap).
